# File: ewsonprem_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# To Grant access to a user's mailbox to another, read the command found at the following location
# https://technet.microsoft.com/en-us/library/bb124097(v=exchg.160).aspx
# Basically it's the use of the Add-MailboxPermission cmdlet
# >Add-MailboxPermission "User Two" -User "Phantom User" -AccessRights FullAccess
# to grant the Phantom User access to User Two's mail box
# The following command grants the administrator access to everybody's mail box
# Get-Mailbox -ResultSize unlimited -Filter {(RecipientTypeDetails -eq 'UserMailbox') -and (Alias -ne 'Admin')} | Add-MailboxPermission -User admin@contoso.com -AccessRights fullaccess -InheritanceType all # noqa
# Apparently it should work for exchange online _also_
# Removing privileges is done by running
# Remove-MailboxPermission -Identity Test1 -User Test2 -AccessRights FullAccess -InheritanceType All
# This example removes user Administrator's full access rights to user Phantom's mailbox.
# >Remove-MailboxPermission -Identity Phantom -User Administrator -AccessRights FullAccess -InheritanceType All
import base64
import email
import imp
import json
import os
import re
import sys
import uuid
from datetime import datetime
from email.header import decode_header
from email.parser import HeaderParser

import phantom.app as phantom
import phantom.rules as phantom_rules
import phantom.utils as ph_utils
import requests
import xmltodict
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from requests.structures import CaseInsensitiveDict

import ews_soap
from ewsonprem_consts import *
from process_email import ProcessEmail

try:
    import urllib
except Exception:
    import urllib.error
    import urllib.parse
    import urllib.request


app_dir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.insert(0, '{}/dependencies/ews_dep'.format(app_dir))  # noqa
from requests_ntlm import HttpNtlmAuth  # noqa


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


class RetVal2(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal2, (val1, val2))


class EWSOnPremConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_DELETE_EMAIL = "delete_email"
    ACTION_ID_UPDATE_EMAIL = "update_email"
    ACTION_ID_COPY_EMAIL = "copy_email"
    ACTION_ID_MOVE_EMAIL = "move_email"
    ACTION_ID_EXPAND_DL = "expand_dl"
    ACTION_ID_RESOLVE_NAME = "resolve_name"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_GET_EMAIL = "get_email"
    REPLACE_CONST = "C53CEA8298BD401BA695F247633D0542"  # pragma: allowlist secret

    def __init__(self):
        """ """
        self.__id_to_name = {}

        # Call the BaseConnectors init first
        super(EWSOnPremConnector, self).__init__()

        self._version = None

        self._session = None

        self._unify_cef_fields = None

        # Target user in case of impersonation
        self._target_user = None

        self._state_file_path = None
        self._state = {}

        self._impersonate = False
        self._dup_emails = 0
        self._skipped_emails = 0
        self._group_list = list()

    def _handle_preprocess_scipts(self):

        config = self.get_config()
        script = config.get('preprocess_script')

        self._preprocess_container = lambda x: x

        if script:
            try:  # Try to laod in script to preprocess artifacts
                if self._python_version < 3:
                    self._script_module = imp.new_module('preprocess_methods')
                    exec(script, self._script_module.__dict__)
                else:
                    import importlib.util
                    preprocess_methods = importlib.util.spec_from_loader('preprocess_methods', loader=None)
                    self._script_module = importlib.util.module_from_spec(preprocess_methods)
                    exec(script, self._script_module.__dict__)
            except Exception as e:
                self.save_progress("Error loading custom script. Error: {}".format(str(e)))
                return self.set_status(phantom.APP_ERROR, EWSONPREM_ERR_CONNECTIVITY_TEST)

            try:
                self._preprocess_container = self._script_module.preprocess_container
            except Exception:
                self.save_progress("Error loading custom script. Does not contain preprocess_container function")
                return self.set_status(phantom.APP_ERROR, EWSONPREM_ERR_CONNECTIVITY_TEST)

        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        try:
            if not float(parameter).is_integer():
                return action_result.set_status(phantom.APP_ERROR, EWSONPREM_VALIDATE_INTEGER_MESSAGE.format(key=key)), None

            parameter = int(parameter)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, EWSONPREM_VALIDATE_INTEGER_MESSAGE.format(key=key)), None

        if parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-negative integer value in the "{}" parameter'
                    .format(key)), None
        if not allow_zero and parameter == 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer value in the '{}' parameter".format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _handle_py_ver_compat_for_input_unicode(self, input_str):
        """
        This method returns the unicode|string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; input_str converted to Unicode - Python 2')
        """
        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup
        except Exception:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string|unicode")

        return input_str

    def _get_string(self, input_str, charset):

        try:
            if input_str:
                if self._python_version == 2:
                    input_str = UnicodeDammit(input_str).unicode_markup.encode(charset)
                else:
                    input_str = UnicodeDammit(input_str).unicode_markup.encode(charset).decode(charset)
        except Exception:
            self.debug_print("Error occurred while converting to string with specific encoding")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = EWSONPREM_ERR_CODE_MESSAGE
                    error_msg = e.args[0]
            else:
                error_code = EWSONPREM_ERR_CODE_MESSAGE
                error_msg = EWSONPREM_ERR_MESSAGE
        except Exception:
            error_code = EWSONPREM_ERR_CODE_MESSAGE
            error_msg = EWSONPREM_ERR_MESSAGE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MESSAGE
        except Exception:
            error_msg = EWSONPREM_ERR_MESSAGE

        return error_code, error_msg

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, STATE_FILE_CORRUPT_ERR)

        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Content-Type': 'text/xml; charset=utf-8', 'Accept': 'text/xml'}

        self._version = config.get('version', '2010')

        self._session = requests.Session()

        self._base_url = config[EWSONPREM_JSON_DEVICE_URL]

        self._unify_cef_fields = config.get('unify_cef_fields', False)

        password = config[phantom.APP_JSON_PASSWORD]
        username = self._handle_py_ver_compat_for_input_str(config[phantom.APP_JSON_USERNAME])
        username = username.replace('/', '\\')

        self._session.auth = HttpNtlmAuth(username, password)

        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        # The host member extacts the host from the URL, is used in creating status messages
        self._host = self._base_url[self._base_url.find('//') + 2:]

        self._impersonate = config.get(EWS_JSON_USE_IMPERSONATE, False)

        ret = self._handle_preprocess_scipts()
        if phantom.is_fail(ret):
            return ret

        return phantom.APP_SUCCESS

    def _get_error_details(self, resp_json):
        """ Function that parses the error json recieved from the device and placed into a json"""

        error_details = {"message": "Not Found", "code": "Not supplied"}

        if not resp_json:
            return error_details

        error_details['message'] = resp_json.get('m:MessageText', 'Not Speficied')
        error_details['code'] = resp_json.get('m:ResponseCode', 'Not Specified')

        return error_details

    def _create_aqs(self, subject, sender, body):
        aqs_str = ""
        if subject:
            aqs_str += "subject:\"{}\" ".format(subject)
        if sender:
            aqs_str += "from:\"{}\" ".format(sender)
        if body:
            aqs_str += "body:\"{}\" ".format(body)

        return aqs_str.strip()

    # TODO: Should change these function to be parameterized, instead of one per type of request
    def _check_get_attachment_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetAttachmentResponse']['m:ResponseMessages']['m:GetAttachmentResponseMessage']

    def _check_getitem_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetItemResponse']['m:ResponseMessages']['m:GetItemResponseMessage']

    def _check_find_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:FindItemResponse']['m:ResponseMessages']['m:FindItemResponseMessage']

    def _check_delete_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:DeleteItemResponse']['m:ResponseMessages']['m:DeleteItemResponseMessage']

    def _check_update_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:UpdateItemResponse']['m:ResponseMessages']['m:UpdateItemResponseMessage']

    def _check_copy_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:CopyItemResponse']['m:ResponseMessages']['m:CopyItemResponseMessage']

    def _check_move_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:MoveItemResponse']['m:ResponseMessages']['m:MoveItemResponseMessage']

    def _check_expand_dl_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:ExpandDLResponse']['m:ResponseMessages']['m:ExpandDLResponseMessage']

    def _check_findfolder_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:FindFolderResponse']['m:ResponseMessages']['m:FindFolderResponseMessage']

    def _check_getfolder_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetFolderResponse']['m:ResponseMessages']['m:GetFolderResponseMessage']

    def _check_resolve_names_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:ResolveNamesResponse']['m:ResponseMessages']['m:ResolveNamesResponseMessage']

    def _parse_fault_node(self, result, fault_node):

        fault_code = fault_node.get('faultcode', {}).get('#text', 'Not specified')
        fault_string = fault_node.get('faultstring', {}).get('#text', 'Not specified')

        return result.set_status(phantom.APP_ERROR,
                'Error occurred, Code: {0} Detail: {1}'.format(fault_code, fault_string))

    def _clean_xml(self, input_xml):

        # But before we do that clean up the xml, MS is known to send invalid xml chars, that it's own msxml library deems as invalid
        # https://support.microsoft.com/en-us/kb/315580
        replace_regex = r"&#x([0-8]|[b-cB-C]|[e-fE-F]|1[0-9]|1[a-fA-F]);"
        clean_xml, number_of_substitutes = re.subn(replace_regex, '', input_xml)

        self.debug_print("Cleaned xml with {0} substitutions".format(number_of_substitutes))

        return clean_xml

    def _get_http_error_details(self, r):

        if 'text/xml' in r.headers.get('Content-Type', ''):
            # Try a xmltodict parse
            try:
                resp_json = xmltodict.parse(self._clean_xml(r.text))

                # convert from OrderedDict to plain dict
                resp_json = json.loads(json.dumps(resp_json))
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("Error occurred while parsing the HTTP error response. {0}".format(error_text))
                return "Unable to parse error details"

            try:
                return resp_json['s:Envelope']['s:Body']['s:Fault']['detail']['e:Message']['#text']
            except Exception:
                pass

        return ""

    def _make_rest_call(self, result, data, check_response, data_string=False):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers
        Needs to return two values, 1st the phantom.APP_[SUCCESS|ERROR], 2nd the response
        """

        # Get the config
        config = self.get_config()

        resp_json = None

        if self._impersonate and not self._target_user:
            return (result.set_status(phantom.APP_ERROR, "Impersonation is required, but target user not set. Cannot continue execution"), None)

        if self._impersonate:
            data = ews_soap.add_to_envelope(data, self._version, self._target_user)
        else:
            data = ews_soap.add_to_envelope(data, self._version)

        data = ews_soap.get_string(data)

        self.debug_print(data)

        # Make the call
        try:
            r = self._session.post(self._base_url, data=data, headers=self._headers, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_SERVER_CONNECTION, error_text), resp_json)

        try:
            resp_body = r.text
        except UnicodeEncodeError:
            self.debug_print('Grabbing r.text failed, using r.content instead')
            resp_body = r.content
            import string
            resp_body = ''.join([x for x in resp_body if x in string.printable])

        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_status_code': r.status_code})
            result.add_debug_data({'r_text': resp_body if r else 'r is None'})
            result.add_debug_data({'r_headers': r.headers})

        if not (200 <= r.status_code <= 399):
            # error
            detail = self._get_http_error_details(r)
            if detail:
                return (result.set_status(phantom.APP_ERROR,
                    "Call failed with HTTP Code: {0}. Reason: {1}. Details: {2}".format(r.status_code, r.reason, detail)), None)
            return (result.set_status(phantom.APP_ERROR,
                "Call failed with HTTP Code: {0}. Reason: {1}".format(r.status_code, r.reason)), None)

        # Try a xmltodict parse
        try:
            resp_json = xmltodict.parse(self._clean_xml(resp_body))

            # convert from OrderedDict to plain dict
            resp_json = json.loads(json.dumps(resp_json))
        except Exception as e:
            # resp_body is guaranteed to be NON None, it will be empty, but not None
            msg_string = EWSONPREM_ERR_JSON_PARSE.format(raw_text=resp_body)
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, msg_string, error_text), resp_json)

        # Check if there is a fault node present
        fault_node = resp_json.get('s:Envelope', {}).get('s:Body', {}).get('s:Fault')

        if fault_node:
            return (self._parse_fault_node(result, fault_node), None)

        # Now try getting the response message
        try:
            resp_message = check_response(resp_json)
        except Exception as e:
            msg_string = EWSONPREM_ERR_JSON_PARSE.format(raw_text=resp_body)
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, msg_string, error_text), resp_json)

        if not isinstance(resp_message, dict):
            return (phantom.APP_SUCCESS, resp_message)

        resp_class = resp_message.get('@ResponseClass', '')

        if resp_class == 'Error':
            if resp_message.get('m:ResponseCode') == EWSONPREM_ERROR_MIME_CONTENT_CONVERSION:
                return (phantom.APP_SUCCESS, resp_message)
            return (result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_FROM_SERVER.format(**(self._get_error_details(resp_message)))), resp_json)

        return (phantom.APP_SUCCESS, resp_message)

    def _test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers."""

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, email_infos = self._get_email_infos_to_process(0, 1, action_result)

        # Process errors
        if phantom.is_fail(ret_val):

            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            action_result.append_to_message(EWS_MODIFY_CONFIG)

            # Set the status of the complete connector result
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())

            # Append the message to display
            action_result.append_to_message(EWSONPREM_ERR_CONNECTIVITY_TEST)

            # return error
            return phantom.APP_ERROR

        # Set the status of the connector result
        self.save_progress(EWSONPREM_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_child_folder_infos(self, user, action_result, parent_folder_info):

        step_size = 500
        folder_infos = list()

        for curr_step_value in range(0, 10000, step_size):

            curr_range = "{0}-{1}".format(curr_step_value, curr_step_value + step_size - 1)

            input_xml = ews_soap.xml_get_children_info(user, parent_folder_id=parent_folder_info['id'], query_range=curr_range)

            ret_val, resp_json = self._make_rest_call(action_result, input_xml, self._check_findfolder_response)

            if phantom.is_fail(ret_val):
                return (action_result.get_status(), None)

            total_items = resp_json.get('m:RootFolder', {}).get('@TotalItemsInView', '0')

            if total_items == '0':
                # total_items gives the total items in the view, not just items returned in the current call
                return (action_result.set_status(phantom.APP_ERROR, "Children not found, possibly not present."), None)

            folders = resp_json.get('m:RootFolder', {}).get('t:Folders', {}).get('t:Folder')

            if not folders:
                return (action_result.set_status(phantom.APP_ERROR, "Folder information not found in response, possibly not present"), None)

            if not isinstance(folders, list):
                folders = [folders]

            folder_infos.extend([{
                'id': x['t:FolderId']['@Id'],
                'display_name': x['t:DisplayName'],
                'children_count': x['t:ChildFolderCount'],
                'folder_path': self._extract_folder_path(x.get('t:ExtendedProperty'))} for x in folders])

            curr_folder_len = len(folders)
            if curr_folder_len < step_size:

                # got less than what we asked for, so looks like we got all that we wanted
                break

            '''
            for folder_info in folder_infos:
                if (int(folder_info['children_count']) <= 0):
                    continue
                curr_ar = ActionResult()
                ret_val, child_folder_infos = self._get_child_folder_infos(user, curr_ar, folder_info)
                if (ret_val):
                    folder_infos.extend(child_folder_infos)
            '''

        return (phantom.APP_SUCCESS, folder_infos)

    def _cleanse_key_names(self, input_dict):

        if not input_dict:
            return input_dict

        if not isinstance(input_dict, dict):
            return input_dict

        for k, v in list(input_dict.items()):
            if k.find(':') != -1:
                new_key = k.replace(':', '_')
                input_dict[new_key] = v
                del input_dict[k]
            if isinstance(v, dict):
                input_dict[new_key] = self._cleanse_key_names(v)
            if isinstance(v, list):

                new_v = []

                for curr_v in v:
                    new_v.append(self._cleanse_key_names(curr_v))

                input_dict[new_key] = new_v

        return input_dict

    def _validate_range(self, email_range, action_result):

        try:
            mini, maxi = (int(x) for x in email_range.split('-'))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse the range. Please specify the range as min_offset-max_offset")

        if mini < 0 or maxi < 0:
            return action_result.set_status(phantom.APP_ERROR, "Invalid min or max offset value specified in range", )

        if mini > maxi:
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value, min_offset greater than max_offset")

        if maxi > EWSONPREM_MAX_END_OFFSET_VAL:
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value. The max_offset value cannot be greater than {0}"
                    .format(EWSONPREM_MAX_END_OFFSET_VAL))

        return (phantom.APP_SUCCESS)

    def _run_query(self, param):
        """ Action handler for the 'run query' action"""

        action_result = self.add_action_result(ActionResult(dict(param)))

        subject = self._handle_py_ver_compat_for_input_str(param.get(EWSONPREM_JSON_SUBJECT, ""))
        sender = self._handle_py_ver_compat_for_input_str(param.get(EWSONPREM_JSON_FROM, ""))
        body = self._handle_py_ver_compat_for_input_str(param.get(EWSONPREM_JSON_BODY, ""))
        int_msg_id = self._handle_py_ver_compat_for_input_str(param.get(EWSONPREM_JSON_INT_MSG_ID, ""))
        aqs = param.get(EWSONPREM_JSON_QUERY, "")
        is_public_folder = param.get(EWS_JSON_IS_PUBLIC_FOLDER, False)

        try:
            if aqs:
                UnicodeDammit(aqs).unicode_markup
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Parameter validation failed for the AQS query. {0}".format(error_text))
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the query. Unicode value found.")

        if not subject and not sender and not aqs and not body and not int_msg_id:
            return action_result.set_status(phantom.APP_ERROR, "Please specify at-least one search criteria")

        # Use parameters to create an aqs string
        '''
        if (not aqs):
            aqs = self._create_aqs(subject, sender, body)
        '''

        self.debug_print("AQS_STR: {}".format(UnicodeDammit(aqs).unicode_markup.encode('utf-8')))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        user = self._handle_py_ver_compat_for_input_str(param[EWSONPREM_JSON_EMAIL])
        folder_path = self._handle_py_ver_compat_for_input_str(param.get(EWSONPREM_JSON_FOLDER))
        self._target_user = user
        ignore_subfolders = param.get('ignore_subfolders', False)

        self.save_progress("Searching in {0}\\{1}{2}".format(
            self._clean_str(user),
            folder_path if folder_path else 'All Folders',
            ' (and the children)' if (not ignore_subfolders) else ''))

        email_range = param.get(EWSONPREM_JSON_RANGE, "0-10")

        ret_val = self._validate_range(email_range, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        folder_infos = []

        if folder_path:
            # get the id of the folder specified
            ret_val, folder_info = self._get_folder_info(user, folder_path, action_result, is_public_folder)
        else:
            ret_val, folder_info = self._get_root_folder_id(user, action_result, is_public_folder)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        parent_folder_info = folder_info
        folder_infos.append(folder_info)

        if not ignore_subfolders:
            if int(parent_folder_info['children_count']) != 0:
                ret_val, child_folder_infos = self._get_child_folder_infos(user, action_result, parent_folder_info=parent_folder_info)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                folder_infos.extend(child_folder_infos)

        items_matched = 0

        num_folder_ids = len(folder_infos)

        self.save_progress('Will be searching in {0} folder{1}', num_folder_ids, 's' if num_folder_ids > 1 else '')

        for i, folder_info in enumerate(folder_infos):

            folder_id = folder_info['id']

            self.send_progress(EWSONPREM_SEARCH_FINISHED_STATUS, float(i) / float(num_folder_ids))

            ar_folder = ActionResult()
            if aqs:
                data = ews_soap.get_search_request_aqs([folder_id], aqs, email_range)
            else:
                data = ews_soap.get_search_request_filter([folder_id], subject=subject, sender=sender,
                                                          body=body, int_msg_id=int_msg_id, email_range=email_range)

            ret_val, resp_json = self._make_rest_call(ar_folder, data, self._check_find_response)

            # Process errors
            if phantom.is_fail(ret_val):
                self.debug_print("Rest call failed: {0}".format(ar_folder.get_message()))
                continue

            resp_json = resp_json.get('m:RootFolder')

            if not resp_json:
                self.debug_print('Result does not contain RootFolder key')
                continue

            resp_items = resp_json.get('t:Items')

            if resp_items is None:
                self.debug_print("items is None")
                continue

            items = []
            for key, value in resp_items.items():
                if isinstance(value, dict):
                    items.append(value)
                elif isinstance(value, list):
                    items.extend(value)
                else:
                    self.debug_print("Skipping the {} key with value {} as it is not in the expected format".format(key, value))

            items_matched += len(items)

            for curr_item in items:
                self._cleanse_key_names(curr_item)
                curr_item['folder'] = folder_info['display_name']
                curr_item['folder_path'] = folder_info.get('folder_path')

                action_result.add_data(curr_item)

        action_result.update_summary({'emails_matched': items_matched})

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_container_id(self, email_id):

        try:
            email_id = urllib.quote_plus(email_id)
        except Exception:
            email_id = urllib.parse.quote_plus(email_id)
        temp_base_url = self.get_phantom_base_url()
        url = temp_base_url + 'rest/container?_filter_source_data_identifier="{0}"&_filter_asset={1}'.format(email_id, self.get_asset_id())

        try:
            # Ignored the verify semgrep check as the following is a call to the phantom's REST API on the instance itself
            r = requests.get(url, verify=False)  # nosemgrep
            resp_json = r.json()
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Unable to query Email container", error_text)
            return None

        if resp_json.get('count', 0) <= 0:
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Container results, not proper", error_text)
            return None

        return container_id

    def _get_email_data_from_container(self, container_id, action_result):

        email_data = None
        email_id = None
        resp_data = {}

        ret_val, resp_data, status_code = self.get_container_info(container_id)

        if phantom.is_fail(ret_val):
            return RetVal3(action_result.set_status(phantom.APP_ERROR, str(resp_data)), email_data, email_id)

        # Keep pylint happy
        resp_data = dict(resp_data)

        email_data = resp_data.get('data', {}).get('raw_email')
        email_id = resp_data['source_data_identifier']

        if not email_data:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                "Container does not seem to be created by the same app, raw_email data not found."), None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_email_data_from_vault(self, vault_id, action_result):

        email_data = None
        email_id = vault_id
        file_path = None

        try:
            success, message, file_info = phantom_rules.vault_info(vault_id=vault_id)
            if not file_info:
                return RetVal3(action_result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_VAULT_INFO), None, None)
            file_path = list(file_info)[0].get('path')
        except Exception:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_VAULT_INFO), None, None)

        if not file_path:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"), None, None)

        try:
            with open(file_path, 'r') as f:
                email_data = f.read()
        except Exception:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "Error occurred while reading vault file"), None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_mail_header_dict(self, email_data, action_result):

        try:
            mail = email.message_from_string(email_data)
        except Exception:
            return RetVal2(action_result.set_status(phantom.APP_ERROR,
                    "Unable to create email object from data. Does not seem to be valid email"), None)

        headers = mail.__dict__.get('_headers')

        if not headers:
            return RetVal2(action_result.set_status(phantom.APP_ERROR,
                    "Could not extract header info from email object data. Does not seem to be valid email"), None)

        ret_val = {}
        for header in headers:
            ret_val[header[0]] = header[1]

        return RetVal2(phantom.APP_SUCCESS, ret_val)

    def _decode_uni_string(self, input_str, def_name):

        # try to find all the decoded strings, we could have multiple decoded strings
        # or a single decoded string between two normal strings separated by \r\n
        # YEAH...it could get that messy
        encoded_strings = re.findall(r'=\?.*\?=', input_str, re.I)

        # return input_str as is, no need to do any conversion
        if not encoded_strings:
            return input_str

        # get the decoded strings
        try:
            decoded_strings = [decode_header(x)[0] for x in encoded_strings]
            decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Decoding: {0}. {1}".format(encoded_strings, err))
            return def_name

        # convert to dict for safe access, if it's an empty list, the dict will be empty
        decoded_strings = dict(enumerate(decoded_strings))

        new_str = ''
        new_str_create_count = 0
        for i, encoded_string in enumerate(encoded_strings):

            decoded_string = decoded_strings.get(i)

            if not decoded_string:
                # nothing to replace with
                continue

            value = decoded_string.get('value')
            encoding = decoded_string.get('encoding')

            if not encoding or not value:
                # nothing to replace with
                continue

            try:
                # Some non-ascii characters were causing decoding issue with
                # the UnicodeDammit and working correctly with the decode function.
                # keeping previous logic in the except block incase of failure.
                value = value.decode(encoding)
                new_str += value
                new_str_create_count += 1
            except Exception:
                try:
                    if encoding != 'utf-8':
                        value = str(value, encoding)
                except Exception:
                    pass

                try:
                    # commenting the existing approach due to a new approach being deployed below
                    # substitute the encoded string with the decoded one
                    # input_str = input_str.replace(encoded_string, value)

                    # make new string insted of replacing in the input string because issue find in PAPP-9531
                    if value:
                        new_str += UnicodeDammit(value).unicode_markup
                        new_str_create_count += 1
                except Exception:
                    pass

        # replace input string with new string because issue find in PAPP-9531
        if new_str and new_str_create_count == len(encoded_strings):
            self.debug_print("Creating a new string entirely from the encoded_strings and assigning into input_str")
            input_str = new_str

        return input_str

    def _get_email_headers_from_mail(self, mail, charset=None, email_headers=None):

        if mail:
            email_headers = list(mail.items())  # it's gives message headers

            if charset is None:
                charset = mail.get_content_charset()

        if not charset:
            charset = 'utf-8'

        if not email_headers:
            return {}

        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        try:
            [headers.update({x[0]: self._get_string(x[1], charset)}) for x in email_headers]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while converting the header tuple into a dictionary"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        # Handle received seperately
        try:
            received_headers = list()
            received_headers = [self._get_string(x[1], charset) for x in email_headers if x[0].lower() == 'received']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while handling the received header tuple separately"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        if received_headers:
            headers['Received'] = received_headers

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')
        if subject:
            if isinstance(subject, str):
                headers['decodedSubject'] = self._decode_uni_string(subject, subject).replace('\r\n', '')

        return headers

    def _handle_email_with_container_id(self, action_result, container_id, ingest_email, target_container_id=None):

        ret_val, email_data, email_id = self._get_email_data_from_container(container_id, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({"email_id": email_id})

        ret_val, header_dict = self._get_mail_header_dict(email_data, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(header_dict)

        if not ingest_email:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched email headers")

        config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True }

        process_email = ProcessEmail()
        ret_val, message = process_email.process_email(self, email_data, email_id, config, None, target_container_id)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        # get the container id that of the email that was ingested
        container_id = self._get_container_id(email_id)

        action_result.update_summary({"container_id": container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_email_with_vault_id(self, action_result, vault_id, ingest_email, target_container_id=None):

        ret_val, email_data, email_id = self._get_email_data_from_vault(vault_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            mail = email.message_from_string(email_data)
            headers = self._get_email_headers_from_mail(mail)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Unable to get email header string from message. {0}".format(error_text)), None

        if not headers:
            return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the headers information from the provided file"), None

        action_result.add_data(dict(headers))

        if not ingest_email:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched email headers")

        config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True }

        process_email = ProcessEmail()
        ret_val, message = process_email.process_email(self, email_data, email_id, config, None, target_container_id)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        # get the container id that of the email that was ingested
        container_id = self._get_container_id(email_id)

        action_result.update_summary({"container_id": container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        email_id = self._handle_py_ver_compat_for_input_unicode(param.get(EWSONPREM_JSON_ID, ""))
        container_id = param.get(EWS_JSON_CONTAINER_ID)
        vault_id = param.get(EWS_JSON_VAULT_ID)
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)
        use_current_container = param.get('use_current_container')
        target_container_id = None

        if container_id is not None:
            ret_val, container_id = self._validate_integer(action_result, container_id, "container_id")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        if use_current_container:
            target_container_id = self.get_container_id()

        if not email_id and not container_id and not vault_id:
            return action_result.set_status(phantom.APP_ERROR, "Please specify id, container_id or vault_id to get the email")

        ingest_email = param.get(EWSONPREM_JSON_INGEST_EMAIL, False)

        if container_id is not None:
            return self._handle_email_with_container_id(action_result, container_id, ingest_email, target_container_id)
        if vault_id is not None:
            return self._handle_email_with_vault_id(action_result, vault_id, ingest_email, target_container_id)
        else:
            data = ews_soap.xml_get_emails_data([email_id], self._version)

            ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

            # Process errors
            if phantom.is_fail(ret_val):
                message = "Error while getting email data for id {0}. Error: {1}".format(self._handle_py_ver_compat_for_input_str(email_id),
                        action_result.get_message())
                self.debug_print(message)
                self.send_progress(message)
                return phantom.APP_ERROR

            if resp_json.get('m:ResponseCode') == EWSONPREM_ERROR_MIME_CONTENT_CONVERSION:
                self.debug_print(EWSONPREM_MIME_CONTENT_CONVERSION_ERROR)
                return action_result.set_status(phantom.APP_ERROR, EWSONPREM_MIME_CONTENT_CONVERSION_ERROR)

            self._cleanse_key_names(resp_json)

            """
            ret_val, rfc822_format = self._get_rfc822_format(resp_json, action_result)
            if (phantom.is_fail(ret_val)):
                return phantom.APP_ERROR

            if (not rfc822_format):
                return action_result.set_status(phantom.APP_ERROR, 'Result does not contain rfc822 data')
            """

            resp_items = resp_json.get('m_Items')
            if not resp_items or not isinstance(resp_items, dict):
                message = {}
            else:
                message = next(iter(resp_items.values()))

            # Remove mime content because it can be very large
            if 't_MimeContent' in message:
                message.pop('t_MimeContent')

            action_result.add_data(message)

            recipients_mailbox = message.get('t_ToRecipients', {}).get('t_Mailbox')

            if recipients_mailbox and (not isinstance(recipients_mailbox, list)):
                message['t_ToRecipients']['t_Mailbox'] = [recipients_mailbox]

            summary = {'subject': message.get('t_Subject'),
                    'create_time': message.get('t_DateTimeCreated'),
                    'sent_time': message.get('t_DateTimeSent')}

            action_result.update_summary(summary)

            if not ingest_email:
                return action_result.set_status(phantom.APP_SUCCESS)

            try:
                self._process_email_id(email_id, target_container_id)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("Error occurred in _process_email_id with Message ID: {0}. {1}".format(email_id, error_text))
                action_result.update_summary({"container_id": None})
                return action_result.set_status(phantom.APP_ERROR, "Error processing email. {0}".format(error_text))

        if target_container_id is None:
            # get the container id that of the email that was ingested
            container_id = self._get_container_id(email_id)
            action_result.update_summary({"container_id": container_id})
        else:
            action_result.update_summary({"container_id": target_container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        email_id = self._handle_py_ver_compat_for_input_unicode(param[EWSONPREM_JSON_ID])
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)
        category = self._handle_py_ver_compat_for_input_unicode(param.get('category'))
        subject = self._handle_py_ver_compat_for_input_unicode(param.get('subject'))

        if subject is None and category is None:
            return action_result.set_status(phantom.APP_ERROR, "Please specify one of the email properties to update")

        # do a get on the message to get the change id
        data = ews_soap.xml_get_emails_data([email_id], self._version)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if phantom.is_fail(ret_val):
            message = "Error while getting email data for id {0}. Error: {1}".format(self._handle_py_ver_compat_for_input_str(email_id),
                    action_result.get_message())
            self.debug_print(message)
            self.send_progress(message)
            return phantom.APP_ERROR

        if resp_json.get('m:ResponseCode') == EWSONPREM_ERROR_MIME_CONTENT_CONVERSION:
            self.debug_print(EWSONPREM_MIME_CONTENT_CONVERSION_ERROR)
            return action_result.set_status(phantom.APP_ERROR, EWSONPREM_MIME_CONTENT_CONVERSION_ERROR)

        try:
            change_key = next(iter(resp_json['m:Items'].values()))['t:ItemId']['@ChangeKey']
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Unable to get the change key of the email to update")

        if category is not None:
            category = [x.strip() for x in category.split(',')]
            category = list(filter(None, category))

        data = ews_soap.get_update_email(email_id, change_key, category, subject)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_update_response)

        # Process errors
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not resp_json:
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        data = ews_soap.xml_get_emails_data([email_id], self._version)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._cleanse_key_names(resp_json)

        resp_items = resp_json.get('m_Items')
        if not resp_items or not isinstance(resp_items, dict):
            message = {}
        else:
            message = next(iter(resp_items.values()))

        categories = message.get('t_Categories', {}).get('t_String')
        if categories:
            if not isinstance(categories, list):
                categories = [categories]
            message['t_Categories'] = categories

        action_result.add_data(message)

        recipients_mailbox = message.get('t_ToRecipients', {}).get('t_Mailbox')

        if recipients_mailbox and (not isinstance(recipients_mailbox, list)):
            message['t_ToRecipients']['t_Mailbox'] = [recipients_mailbox]

        summary = {'subject': message.get('t_Subject'),
                'create_time': message.get('t_DateTimeCreated'),
                'sent_time': message.get('t_DateTimeSent')}

        action_result.update_summary(summary)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _delete_email(self, param):

        action_result = ActionResult(dict(param))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = self._handle_py_ver_compat_for_input_unicode(param[EWSONPREM_JSON_ID])
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)

        message_ids = ph_utils.get_list_from_string(message_id)

        data = ews_soap.get_delete_email(message_ids)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_delete_response)

        # Process errors
        if phantom.is_fail(ret_val):
            self.add_action_result(action_result)
            return action_result.get_status()

        if not resp_json:
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        if not isinstance(resp_json, list):
            resp_json = [resp_json]

        for msg_id, resp_message in zip(message_ids, resp_json):

            curr_param = dict(param)
            curr_param.update({"id": msg_id})
            curr_ar = self.add_action_result(ActionResult(curr_param))

            resp_class = resp_message.get('@ResponseClass', '')

            if resp_class == 'Error':
                curr_ar.set_status(phantom.APP_ERROR, EWSONPREM_ERR_FROM_SERVER.format(**(self._get_error_details(resp_message))))
                continue
            curr_ar.set_status(phantom.APP_SUCCESS, "Email deleted")

        # Set the Status
        return phantom.APP_SUCCESS

    def _clean_str(self, string):

        if not string:
            return ''

        return string.replace('{', '-').replace('}', '-')

    def _extract_folder_path(self, extended_property):

        if not extended_property:
            return ''

        # As of right now, the folder path is the only extended property
        # that the app extracts, so parse the value directly, once the app starts
        # parsing other extended properties, the 't:ExtendedFieldURI dictionary will
        # require to be parsed and validated
        value = extended_property.get('t:Value')

        if not value:
            return ''

        value = value.lstrip('\\')

        # I don't know why exchange gives back the path with
        # '\\' separators since '\' is a valid char allowed in a folder name
        # makes things confusing and extra parsing code to be written.
        # Therefore the app treats folder paths with '/' as the separator, keeps
        # things less confusing for users.
        value = value.replace('\\', '/')

        if not value:
            return ''

        return value

    def _get_root_folder_id(self, user, action_result, is_public_folder=False):

        if is_public_folder:
            root_folder_id = 'publicfoldersroot'
        else:
            root_folder_id = 'root'

        folder_info = {'id': root_folder_id, 'display_name': root_folder_id, 'children_count': -1, 'folder_path': ''}

        return (phantom.APP_SUCCESS, folder_info)

    def _get_matching_folder_path(self, folder_list, folder_name, folder_path, action_result):
        """ The input folder is a list, meaning the folder name matched multiple folder
            Given the folder path, this function will return the one that matches, or fail
        """

        if not folder_list:
            return (action_result(phantom.APP_ERROR, "Unable to find info about folder '{0}'. Returned info list empty"
                    .format(folder_name)), None)

        for curr_folder in folder_list:
            curr_folder_path = self._extract_folder_path(curr_folder.get('t:ExtendedProperty'))
            if self._handle_py_ver_compat_for_input_str(curr_folder_path) == folder_path:
                return (phantom.APP_SUCCESS, curr_folder)

        return (action_result.set_status(phantom.APP_ERROR, "Folder paths did not match while searching for folder: '{0}'"
                .format(folder_path)), None)

    def _get_folder_info(self, user, folder_path, action_result, is_public_folder=False):
        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder_path.replace('\\/', self.REPLACE_CONST)
        folder_names = folder_path.split('/')

        folder_names = list(filter(None, folder_names))
        if not folder_names:
            return (action_result.set_status(phantom.APP_ERROR, "Please provide a valid value for folder path"), None)

        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self.REPLACE_CONST, '/')

        if is_public_folder:
            parent_folder_id = 'publicfoldersroot'
        else:
            parent_folder_id = 'root'

        for i, folder_name in enumerate(folder_names):

            curr_valid_folder_path = '/'.join(folder_names[:i + 1])

            self.save_progress('Getting info about {0}\\{1}'.format(self._clean_str(user), curr_valid_folder_path))

            input_xml = ews_soap.xml_get_children_info(user, child_folder_name=folder_name, parent_folder_id=parent_folder_id)

            ret_val, resp_json = self._make_rest_call(action_result, input_xml, self._check_findfolder_response)

            if phantom.is_fail(ret_val):
                return (action_result.get_status(), None)

            total_items = resp_json.get('m:RootFolder', {}).get('@TotalItemsInView', '0')

            if total_items == '0':
                return (action_result.set_status(phantom.APP_ERROR, "Folder '{0}' not found, possibly not present"
                        .format(curr_valid_folder_path)), None)

            folder = resp_json.get('m:RootFolder', {}).get('t:Folders', {}).get('t:Folder')

            if not folder:
                return (action_result.set_status(phantom.APP_ERROR, "Information about '{0}' not found in response, possibly not present"
                        .format(curr_valid_folder_path)), None)

            if not isinstance(folder, list):
                folder = [folder]

            ret_val, folder = self._get_matching_folder_path(folder, folder_name, curr_valid_folder_path, action_result)

            if phantom.is_fail(ret_val):
                return (action_result.get_status(), None)

            if not folder:
                return (action_result.set_status(phantom.APP_ERROR,
                    "Information for folder '{0}' not found in response, possibly not present".format(curr_valid_folder_path)), None)

            folder_id = folder.get('t:FolderId', {}).get('@Id')

            if not folder_id:
                return (action_result.set_status(phantom.APP_ERROR,
                    "Folder ID information not found in response for '{0}', possibly not present".format(curr_valid_folder_path)), None)

            parent_folder_id = folder_id
            folder_info = {'id': folder_id,
                    'display_name': folder.get('t:DisplayName'),
                    'children_count': folder.get('t:ChildFolderCount'),
                    'folder_path': self._extract_folder_path(folder.get('t:ExtendedProperty'))}

        return (phantom.APP_SUCCESS, folder_info)

    def _copy_move_email(self, param, action="copy"):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = self._handle_py_ver_compat_for_input_unicode(param[EWSONPREM_JSON_ID])

        folder_path = self._handle_py_ver_compat_for_input_str(param[EWSONPREM_JSON_FOLDER])
        user = self._handle_py_ver_compat_for_input_str(param[EWSONPREM_JSON_EMAIL])
        is_public_folder = param.get(EWS_JSON_IS_PUBLIC_FOLDER, False)

        # Set the user to impersonate (i.e. target_user), by default it is the destination user
        self._target_user = user

        # Use a different email if specified
        impersonate_email = self._handle_py_ver_compat_for_input_str(param.get(EWS_JSON_IMPERSONATE_EMAIL))
        if impersonate_email:
            self._target_user = impersonate_email

        # finally see if impersonation has been enabled/disabled for this action
        # as of right now copy or move email is the only action that allows over-ride
        impersonate = not(param.get(EWS_JSON_DONT_IMPERSONATE, False))

        self._impersonate = impersonate

        ret_val, folder_info = self._get_folder_info(user, folder_path, action_result, is_public_folder)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = ews_soap.get_copy_email(message_id, folder_info['id'])
        response_checker = self._check_copy_response

        if action == "move":
            data = ews_soap.get_move_email(message_id, folder_info['id'])
            response_checker = self._check_move_response

        ret_val, resp_json = self._make_rest_call(action_result, data, response_checker)

        # Process errors
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not resp_json:
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        new_email_id = None

        action_verb = 'copied' if action == "copy" else 'moved'

        try:
            new_email_id = next(iter(resp_json['m:Items'].values()))['t:ItemId']['@Id']
        except Exception:
            return action_result.set_status(phantom.APP_SUCCESS, "Unable to get {0} Email ID".format(action_verb))

        action_result.add_data({'new_email_id': new_email_id})

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS, "Email {0}".format(action_verb.title()))

    def _resolve_name(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        email = self._handle_py_ver_compat_for_input_str(param[EWSONPREM_JSON_EMAIL])

        self._impersonate = False

        data = ews_soap.xml_get_resolve_names(email)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_resolve_names_response)

        # Process errors
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'ErrorNameResolutionNoResults' in message:
                message = 'No email found. The input parameter might not be a valid alias or email.'
                return action_result.set_status(phantom.APP_SUCCESS, message)
            else:
                return action_result.set_status(phantom.APP_ERROR, message)

        if not resp_json:
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        resolution_set = resp_json.get('m:ResolutionSet', {}).get('t:Resolution')

        if not resolution_set:
            return action_result.set_summary({'total_entries': 0})

        if not isinstance(resolution_set, list):
            resolution_set = [resolution_set]

        action_result.update_summary({'total_entries': len(resolution_set)})

        for curr_resolution in resolution_set:

            self._cleanse_key_names(curr_resolution)

            contact = curr_resolution.get('t_Contact')
            if contact:
                email_addresses = contact.get('t_EmailAddresses', {}).get('t_Entry', [])
                if email_addresses:
                    if not isinstance(email_addresses, list):
                        email_addresses = [email_addresses]
                    contact['t_EmailAddresses'] = email_addresses

            action_result.add_data(curr_resolution)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _expand_dl(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        group = self._handle_py_ver_compat_for_input_str(param[EWSONPREM_JSON_GROUP])
        self._group_list.append(group)

        self._impersonate = False

        data = ews_soap.get_expand_dl(group)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_expand_dl_response)

        # Process errors
        if phantom.is_fail(ret_val):

            message = action_result.get_message()
            if 'ErrorNameResolutionNoResults' in message:
                message += ' The input parameter might not be a distribution list.'
                action_result.add_data({"t_EmailAddress": group})
            return action_result.set_status(phantom.APP_ERROR, message)

        if not resp_json:
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        mailboxes = resp_json.get('m:DLExpansion', {}).get('t:Mailbox')

        if not mailboxes:
            action_result.set_summary({'total_entries': 0})
            return action_result.set_status(phantom.APP_SUCCESS)

        if not isinstance(mailboxes, list):
            mailboxes = [mailboxes]

        action_result.update_summary({'total_entries': len(mailboxes)})

        for mailbox in mailboxes:
            value = any(elem in [mailbox['t:EmailAddress'], mailbox['t:Name']] for elem in self._group_list)
            if param.get('recursive', False) and "DL" in mailbox['t:MailboxType'] and not value:
                param[EWSONPREM_JSON_GROUP] = mailbox['t:EmailAddress']
                self._expand_dl(param)
            self._cleanse_key_names(mailbox)
            action_result.add_data(mailbox)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_email_epoch(self, resp_json):
        return None

    def _get_rfc822_format(self, resp_json, action_result):

        try:
            mime_content = resp_json['m:Items']['t:Message']['t:MimeContent']['#text']
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Email MimeContent missing in response.")

        try:
            rfc822_email = base64.b64decode(mime_content)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Unable to decode Email Mime Content. {0}".format(error_text))
            return action_result.set_status(phantom.APP_ERROR, "Unable to decode Email Mime Content")

        return (phantom.APP_SUCCESS, rfc822_email)

    def _get_attachment_meta_info(self, attachment, curr_key, parent_internet_message_id, parent_guid):

        attach_meta_info = dict()

        try:
            attach_meta_info['attachmentId'] = attachment['t:AttachmentId']['@Id']
        except Exception:
            pass

        try:
            attach_meta_info['attachmentType'] = curr_key[2:].replace('Attachment', '').lower()
        except Exception:
            pass

        attach_meta_info['parentInternetMessageId'] = parent_internet_message_id
        attach_meta_info['parentGuid'] = parent_guid

        # attachmentID, attachmentType
        for k, v in attachment.items():

            if not isinstance(v, str):
                continue

            # convert the key to the convention used by cef
            cef_key_name = k[2:]
            cef_key_name = cef_key_name[0].lower() + cef_key_name[1:]
            attach_meta_info[cef_key_name] = v

        return attach_meta_info

    def _extract_ext_properties_from_attachments(self, resp_json):

        email_headers_ret = list()
        attach_meta_info_ret = list()

        if 'm:Items' not in resp_json:
            k = next(iter(resp_json.keys()))
            resp_json['m:Items'] = resp_json.pop(k)

        data = None
        # Get the attachments
        try:
            for key in EWSONPREM_MAIL_TYPES:
                if key in resp_json['m:Items']:
                    data = resp_json['m:Items'][key]
            attachments = data['t:Attachments']
        except Exception:
            return RetVal3(phantom.APP_SUCCESS)

        attachment_ids = list()

        internet_message_id = None
        try:
            internet_message_id = data['t:InternetMessageId']
        except Exception:
            internet_message_id = None

        email_guid = resp_json['emailGuid']

        for curr_key in list(attachments.keys()):

            attachment_data = attachments[curr_key]

            if not isinstance(attachment_data, list):
                attachment_data = [attachment_data]

            for curr_attachment in attachment_data:

                attachment_ids.append(curr_attachment['t:AttachmentId']['@Id'])
                # Add the info that we have right now
                curr_attach_meta_info = self._get_attachment_meta_info(curr_attachment, curr_key, internet_message_id, email_guid)
                if curr_attach_meta_info:
                    attach_meta_info_ret.append(curr_attach_meta_info)

        if not attachment_ids:
            return RetVal3(phantom.APP_SUCCESS)

        data = ews_soap.xml_get_attachments_data(attachment_ids)

        action_result = ActionResult()

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_get_attachment_response)

        # Process errors
        if phantom.is_fail(ret_val):
            return RetVal3(action_result.get_status())

        if not isinstance(resp_json, list):
            resp_json = [resp_json]

        for curr_attachment_data in resp_json:

            try:
                curr_attachment_data = curr_attachment_data['m:Attachments']
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("Could not parse the attachments response", error_text)
                continue

            curr_attachment_data['emailGuid'] = str(uuid.uuid4())
            ret_val, data = self._extract_ext_properties(curr_attachment_data, internet_message_id, email_guid)

            if data:
                email_headers_ret.append(data)
                ret_val, email_headers_info, attach_meta_info = self._extract_ext_properties_from_attachments(curr_attachment_data)
                if email_headers_info:
                    email_headers_ret.extend(email_headers_info)
                if attach_meta_info:
                    attach_meta_info_ret.extend(attach_meta_info)
            else:
                # This is a file attachment, we most probably already have the info from the resp_json
                # But update it with the call to the xml_get_attachments_data(..) There might be more info
                # that has to be updated
                curr_attach_meta_info = self._get_attachment_meta_info(curr_attachment_data['m:Items'], 't:FileAttachment',
                        internet_message_id, email_guid)
                if curr_attach_meta_info:
                    # find the attachment in the list and update it
                    matched_meta_info = list(filter(lambda x: x.get('attachmentId', 'foo1') == curr_attach_meta_info.get('attachmentId', 'foo2'),
                            attach_meta_info_ret))
                    matched_meta_info[0].update(curr_attach_meta_info)

        return (phantom.APP_SUCCESS, email_headers_ret, attach_meta_info_ret)

    def _extract_email_headers(self, email_headers):

        header_parser = HeaderParser()
        email_part = header_parser.parsestr(email_headers)
        email_headers = list(email_part.items())

        headers = {}
        charset = 'utf-8'

        try:
            [headers.update({x[0]: self._get_string(x[1], charset)}) for x in email_headers]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while converting the header tuple into a dictionary"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        # Handle received seperately
        try:
            received_headers = list()
            received_headers = [self._get_string(x[1], charset) for x in email_headers if x[0].lower() == 'received']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while handling the received header tuple separately"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        if received_headers:
            headers['Received'] = received_headers

        return headers

    def _extract_ext_properties(self, resp_json, parent_internet_message_id=None, parent_guid=None):  # noqa

        if 'm:Items' not in resp_json:
            k = next(iter(resp_json.keys()))
            resp_json['m:Items'] = resp_json.pop(k)

        headers = dict()
        extended_properties = list()

        data = None
        # Get the Extended Properties
        try:
            for key in EWSONPREM_MAIL_TYPES:
                if key in resp_json['m:Items']:
                    data = resp_json['m:Items'][key]
            extended_properties = data['t:ExtendedProperty']
        except Exception:
            pass

        if extended_properties:
            if not isinstance(extended_properties, list):
                extended_properties = [extended_properties]

            for curr_ext_property in extended_properties:

                property_tag = curr_ext_property.get('t:ExtendedFieldURI', {}).get('@PropertyTag')
                value = curr_ext_property.get('t:Value')

                if not property_tag:
                    continue

                if property_tag.lower() in [ews_soap.EXTENDED_PROPERTY_HEADERS.lower(), ews_soap.EXTENDED_PROPERTY_HEADERS_RESPONSE.lower()]:
                    email_headers = self._extract_email_headers(value)
                    if email_headers is not None:
                        headers.update(email_headers)
                        continue
                if property_tag == ews_soap.EXTENDED_PROPERTY_BODY_TEXT:
                    headers.update({'bodyText': value})

        # now parse the body in the main resp_json
        try:
            body_text = data['t:Body']['#text']
        except Exception:
            body_text = None

        try:
            body_type = data['t:Body']['@BodyType']
        except Exception:
            body_type = None

        if body_text is not None:
            if body_type is not None:
                body_key = "body{0}".format(body_type.title().replace(' ', ''))
                headers.update({body_key: body_text})

        # if in the response json we find html body then it will not create body text,
        # so, we have to create body text headers
        if 'bodyText' not in headers:

            # try to find body text if it retrived in the response json
            try:
                self.debug_print("Extracting body text from t:TextBody key from the response")
                body_text = data['t:TextBody']['#text']
            except Exception:
                body_text = None

            # if body text not found into the response json
            # then, try to create body text from fetched body HTML using Beautiful soup parser
            if body_text is None and 'bodyHtml' in headers:
                self.debug_print("Extracting body text from bodyHtml key from the headers")
                try:
                    soup = BeautifulSoup(headers.get('bodyHtml'), "html.parser")
                    if soup.body and soup.body.text:
                        body_text = soup.body.text
                    else:
                        body_text = soup.text
                    split_lines = body_text.split('\n')
                    split_lines = [x.strip() for x in split_lines if x.strip()]
                    body_text = '\n'.join(split_lines)
                except Exception:
                    body_text = None

            if body_text is not None:
                headers['bodyText'] = body_text

        # In some cases the message id is not part of the headers, in this case
        # copy the message id from the envelope to the header
        headers_ci = CaseInsensitiveDict(headers)
        message_id = headers_ci.get('message-id')
        if message_id is None:
            try:
                message_id = data['t:InternetMessageId']
                headers['Message-ID'] = message_id
            except Exception:
                pass

        if parent_internet_message_id is not None:
            headers['parentInternetMessageId'] = parent_internet_message_id

        if parent_guid is not None:
            headers['parentGuid'] = parent_guid

        headers['emailGuid'] = resp_json['emailGuid']
        self.emailGuid = headers['emailGuid']
        if 'parentGuid' in headers:
            self.parentGuid = headers['parentGuid']

        return (phantom.APP_SUCCESS, headers)

    def _parse_email(self, resp_json, email_id, target_container_id):

        try:
            mime_content = next(iter(resp_json['m:Items'].values()))['t:MimeContent']['#text']
        except Exception:
            return (phantom.APP_ERROR, "Email MimeContent missing in response.")

        try:
            rfc822_email = base64.b64decode(mime_content)
            if not self._python_version == 2:
                rfc822_email = UnicodeDammit(rfc822_email).unicode_markup
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Unable to decode Email Mime Content. {0}".format(error_text))
            return (phantom.APP_ERROR, "Unable to decode Email Mime Content")

        epoch = self._get_email_epoch(resp_json)

        email_header_list = list()
        attach_meta_info_list = list()
        resp_json['emailGuid'] = str(uuid.uuid4())

        ret_val, data = self._extract_ext_properties(resp_json)

        if data:
            email_header_list.append(data)

        ret_val, attach_email_headers, attach_meta_info = self._extract_ext_properties_from_attachments(resp_json)

        if attach_email_headers:
            email_header_list.extend(attach_email_headers)

        if attach_meta_info:
            attach_meta_info_list.extend(attach_meta_info)

        process_email = ProcessEmail()
        return process_email.process_email(self, rfc822_email, email_id, self.get_config(), epoch, target_container_id,
                email_headers=email_header_list, attachments_data=attach_meta_info_list)

    def _process_email_id(self, email_id, target_container_id=None):

        data = ews_soap.xml_get_emails_data([email_id], self._version)

        action_result = ActionResult()

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if phantom.is_fail(ret_val):
            message = "Error while getting email data for id {0}. Error: {1}".format(email_id, action_result.get_message())
            self.debug_print(message)
            self.send_progress(message)
            return phantom.APP_ERROR

        if resp_json.get('m:ResponseCode') == EWSONPREM_ERROR_MIME_CONTENT_CONVERSION:
            self.debug_print(EWSONPREM_MIME_CONTENT_CONVERSION_MESSAGE.format(email_id))
            self._skipped_emails += 1
            return phantom.APP_SUCCESS

        ret_val, message = self._parse_email(resp_json, email_id, target_container_id)

        if phantom.is_fail(ret_val):
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _get_email_infos_to_process(self, offset, max_emails, action_result, restriction=None, field_uri="LastModifiedTime"):

        config = self.get_config()

        # get the user
        poll_user = config.get(EWS_JSON_POLL_USER, config[phantom.APP_JSON_USERNAME])

        if not poll_user:
            return (action_result.set_status(phantom.APP_ERROR, "Polling User Email not specified, cannot continue"), None)

        self._target_user = poll_user

        folder_path = self._handle_py_ver_compat_for_input_str(config.get(EWS_JSON_POLL_FOLDER, 'Inbox'))

        is_public_folder = config.get(EWS_JSON_IS_PUBLIC_FOLDER, False)
        ret_val, folder_info = self._get_folder_info(poll_user, folder_path, action_result, is_public_folder)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        manner = config[EWS_JSON_INGEST_MANNER]
        folder_id = folder_info['id']

        order = "Ascending"
        if manner == EWS_INGEST_LATEST_EMAILS:
            order = "Descending"

        data = ews_soap.xml_get_email_ids(
            poll_user,
            order=order,
            offset=offset,
            max_emails=max_emails,
            folder_id=folder_id,
            restriction=restriction,
            field_uri=field_uri
        )

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_find_response)

        # Process errors
        if phantom.is_fail(ret_val):

            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            # return error
            return (action_result.get_status(), None)

        resp_json = resp_json.get('m:RootFolder')

        if not resp_json:
            return (action_result.set_status(phantom.APP_ERROR, 'Result does not contain required RootFolder key'), None)

        resp_items = resp_json.get('t:Items')

        if resp_items is None:
            self.debug_print("items is None")
            return (action_result.set_status(phantom.APP_SUCCESS, 'Result does not contain items key. Possibly no emails in folder'), None)

        items = []
        for key, value in list(resp_items.items()):
            if isinstance(value, dict):
                items.append(value)
            elif isinstance(value, list):
                items.extend(value)
            else:
                self.debug_print("Skipping the {} key with value {} as it is not in the expected format".format(key, value))

        email_infos = [{'id': x['t:ItemId']['@Id'], 'last_modified_time': x['t:LastModifiedTime'],
                'created_time': x['t:DateTimeCreated']} for x in items]

        return (phantom.APP_SUCCESS, email_infos)

    def _pprint_email_id(self, email_id):
        return "{0}.........{1}".format(email_id[:20], email_id[-20:])

    def _process_email_ids(self, email_ids, action_result):

        if email_ids is None:
            return action_result.set_status(phantom.APP_ERROR, "Did not get access to email IDs")

        self.save_progress("Got {0} email{1}".format(len(email_ids), '' if len(email_ids) == 1 else 's'))

        for i, email_id in enumerate(email_ids):
            self.send_progress("Querying email # {0} with id: {1}".format(i + 1, self._pprint_email_id(email_id)))
            try:
                self._process_email_id(email_id)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = EWSONPREM_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("Error occurred in _process_email_id # {0} with Message ID: {1}. {2}".format(i, email_id, error_text))
        if self._skipped_emails > 0:
            self.save_progress("Skipped emails: {}. (For more details, check the logs)".format(self._skipped_emails))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_now(self, param):

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))
        # Get the maximum number of emails that we can pull, same as container count
        max_emails = param[phantom.APP_JSON_CONTAINER_COUNT]
        ret_val, max_emails = self._validate_integer(action_result, max_emails, "container_count")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Will be ingesting all possible artifacts (ignoring max artifacts value) for POLL NOW")

        email_id = param.get(phantom.APP_JSON_CONTAINER_ID)
        email_ids = [email_id]

        # get the user
        poll_user = config.get(EWS_JSON_POLL_USER, config[phantom.APP_JSON_USERNAME])

        if not poll_user:
            return (action_result.set_status(phantom.APP_ERROR, "Polling User Email not specified, cannot continue"), None)

        self._target_user = poll_user

        if not email_id:

            self.save_progress("POLL NOW Getting {0} '{1}' email ids".format(max_emails, config[EWS_JSON_INGEST_MANNER]))
            sort_on = "DateTimeCreated" if config.get(EWS_JSON_INGEST_TIME, "") == "created time" else "LastModifiedTime"
            ret_val, email_infos = self._get_email_infos_to_process(0, max_emails, action_result, field_uri=sort_on)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not email_infos:
                return action_result.set_status(phantom.APP_SUCCESS)
            email_ids = [x['id'] for x in email_infos]
        else:
            self.save_progress("POLL NOW Getting the single email id")

        return self._process_email_ids(email_ids, action_result)

    def _get_restriction(self, field_uri="LastModifiedTime", emails_after="last_email_format"):
        """

        Args:
            field_uri (str, optional): [Sorting field for the email data]
            emails_after (str, optional): [Key to fetch latest ingestion date from the state file]

        Returns:
            [Restriction]: [Restriction to be used in the soap call]
        """

        config = self.get_config()

        emails_after_key = 'last_ingested_format' if config[EWS_JSON_INGEST_MANNER] == EWS_INGEST_LATEST_EMAILS else emails_after

        date_time_string = self._state.get(emails_after_key)

        if not date_time_string:
            return None

        return ews_soap.xml_get_restriction(date_time_string, field_uri=field_uri)

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        # on poll action that is supposed to be scheduled
        if self.is_poll_now():
            self.debug_print("DEBUGGER: Starting polling now")
            return self._poll_now(param)

        config = self.get_config()
        total_ingested = 0

        if self._state.get('first_run', True):
            # set the config to _not_ first run
            self._state['first_run'] = False

            max_emails = config[EWS_JSON_FIRST_RUN_MAX_EMAILS]
            ret_val, max_emails = self._validate_integer(action_result, max_emails, EWS_JSON_FIRST_RUN_MAX_EMAILS)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            run_limit = config[EWS_JSON_FIRST_RUN_MAX_EMAILS]
            ret_val, run_limit = self._validate_integer(action_result, run_limit, EWS_JSON_FIRST_RUN_MAX_EMAILS)

            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            max_emails = config[EWS_JSON_POLL_MAX_CONTAINERS]
            ret_val, max_emails = self._validate_integer(action_result, max_emails, EWS_JSON_POLL_MAX_CONTAINERS)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            run_limit = config[EWS_JSON_POLL_MAX_CONTAINERS]
            ret_val, run_limit = self._validate_integer(action_result, run_limit, EWS_JSON_POLL_MAX_CONTAINERS)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        sort_on = None
        emails_after = None

        # Create sort field and key for last ingested time, based on the asset configuration
        if config.get(EWS_JSON_INGEST_TIME, "") == "created time":
            sort_on = "DateTimeCreated"
            emails_after = "last_created_format"
        else:
            sort_on = "LastModifiedTime"
            emails_after = "last_email_format"

        while True:

            self._dup_emails = 0
            self._skipped_emails = 0
            restriction = self._get_restriction(field_uri=sort_on, emails_after=emails_after)

            ret_val, email_infos = self._get_email_infos_to_process(0, max_emails, action_result, restriction, field_uri=sort_on)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not email_infos:
                return action_result.set_status(phantom.APP_SUCCESS)

            # if the config is for latest emails, then the 0th is the latest in the list returned, else
            # The last email is the latest in the list returned
            email_index = 0 if config[EWS_JSON_INGEST_MANNER] == EWS_INGEST_LATEST_EMAILS else -1

            # Store all the times to the state file for the next cycle
            utc_now = datetime.utcnow()
            self._state['last_ingested_format'] = utc_now.strftime(DATETIME_FORMAT)
            self._state['last_email_format'] = email_infos[email_index]['last_modified_time']
            self._state['last_created_format'] = email_infos[email_index]['created_time']

            email_ids = [x['id'] for x in email_infos]

            ret_val = self._process_email_ids(email_ids, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            total_ingested += max_emails - (self._dup_emails + self._skipped_emails)

            if config[EWS_JSON_INGEST_MANNER] == EWS_INGEST_LATEST_EMAILS or total_ingested >= run_limit:
                break

            # In case of duplicate emails, find the count of duplicate emails and run the cycle again
            sort_field = "created_time" if config.get(EWS_JSON_INGEST_TIME, "") == "created time" else "last_modified_time"
            next_cycle_repeat_emails = 0
            last_email_time = email_infos[email_index][sort_field]
            for email_info in reversed(email_infos):
                if email_info[sort_field] == last_email_time:
                    next_cycle_repeat_emails += 1
                else:
                    break

            max_emails = next_cycle_repeat_emails + min(self._dup_emails + self._skipped_emails, run_limit)

        return ret_val

    def handle_action(self, param):
        """Function that handles all the actions"""

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        # Initialize it to success
        ret_val = phantom.APP_SUCCESS

        # Bunch if if..elif to process actions
        if action == self.ACTION_ID_RUN_QUERY:
            ret_val = self._run_query(param)
        elif action == self.ACTION_ID_DELETE_EMAIL:
            ret_val = self._delete_email(param)
        elif action == self.ACTION_ID_UPDATE_EMAIL:
            ret_val = self._update_email(param)
        elif action == self.ACTION_ID_GET_EMAIL:
            ret_val = self._get_email(param)
        elif action == self.ACTION_ID_COPY_EMAIL:
            ret_val = self._copy_move_email(param)
        elif action == self.ACTION_ID_MOVE_EMAIL:
            ret_val = self._copy_move_email(param, action='move')
        elif action == self.ACTION_ID_EXPAND_DL:
            ret_val = self._expand_dl(param)
        elif action == self.ACTION_ID_RESOLVE_NAME:
            ret_val = self._resolve_name(param)
        elif action == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()
    in_json = None
    in_email = None

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=verify,
                               data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:

        in_json = f.read()
        in_json = json.loads(in_json)

        connector = EWSOnPremConnector()
        connector.print_progress_message = True

        data = in_json.get('data')
        raw_email = in_json.get('raw_email')

        # if neither present then treat it as a normal action test json
        if not data and not raw_email:
            print(json.dumps(in_json, indent=4))

            if session_id is not None:
                in_json['user_session_token'] = session_id
            result = connector._handle_action(json.dumps(in_json), None)
            print(result)
            sys.exit(0)

        if data:
            raw_email = data.get('raw_email')

        if raw_email:
            config = {
                    "extract_attachments": True,
                    "extract_domains": True,
                    "extract_hashes": True,
                    "extract_ips": True,
                    "extract_urls": True,
                    "add_body_to_header_artifacts": True }

            process_email = ProcessEmail()
            ret_val, message = process_email.process_email(connector, raw_email, "manual_parsing", config, None)

    sys.exit(0)
