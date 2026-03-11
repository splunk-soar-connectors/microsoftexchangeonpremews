# Copyright (c) 2016-2026 Splunk Inc.
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

import json
import re

import requests
import xmltodict
from bs4 import UnicodeDammit
from charset_normalizer import from_bytes
from requests_ntlm import HttpNtlmAuth
from soar_sdk.logging import getLogger

from . import ews_soap
from .consts import DEFAULT_REQUEST_TIMEOUT


logger = getLogger()


class EWSHelper:
    def __init__(self, asset):
        self.asset = asset
        self._session = requests.Session()
        self._headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "Accept": "text/xml",
        }
        self._version = asset.version or "2013"
        self._base_url = asset.url.rstrip("/")
        self._target_user = None
        self._impersonate = asset.use_impersonation

        username = asset.username.replace("/", "\\")
        self._session.auth = HttpNtlmAuth(username, asset.password)

    def set_target_user(self, user: str):
        self._target_user = user

    def _clean_xml(self, input_xml: str) -> str:
        replace_regex = r"&#x([0-8]|[b-cB-C]|[e-fE-F]|1[0-9]|1[a-fA-F]);"
        clean_xml, _ = re.subn(replace_regex, "", input_xml)
        return clean_xml

    def _get_http_error_details(self, r) -> str:
        if "text/xml" in r.headers.get("Content-Type", ""):
            try:
                resp_json = xmltodict.parse(self._clean_xml(r.text))
                resp_json = json.loads(json.dumps(resp_json))
                return resp_json["s:Envelope"]["s:Body"]["s:Fault"]["detail"][
                    "e:Message"
                ]["#text"]
            except Exception:
                pass
        return ""

    def _parse_fault_node(self, fault_node: dict) -> str:
        fault_code = fault_node.get("faultcode", {}).get("#text", "Not specified")
        fault_string = fault_node.get("faultstring", {}).get("#text", "Not specified")
        return f"Error occurred, Code: {fault_code} Detail: {fault_string}"

    def make_rest_call(self, data, check_response):
        if self._impersonate and not self._target_user:
            raise ValueError("Impersonation is required, but target user not set")

        if self._impersonate:
            data = ews_soap.add_to_envelope(data, self._version, self._target_user)
        else:
            data = ews_soap.add_to_envelope(data, self._version)

        data = ews_soap.get_string(data)

        try:
            r = self._session.post(
                self._base_url,
                data=data,
                headers=self._headers,
                verify=self.asset.verify_server_cert,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
        except Exception as e:
            raise ConnectionError(f"Connection failed: {e}") from e

        if not (200 <= r.status_code <= 399):
            detail = self._get_http_error_details(r)
            if detail:
                raise Exception(
                    f"Call failed with HTTP Code: {r.status_code}. Reason: {r.reason}. Details: {detail}"
                )
            raise Exception(
                f"Call failed with HTTP Code: {r.status_code}. Reason: {r.reason}"
            )

        try:
            resp_json = xmltodict.parse(self._clean_xml(r.text))
            resp_json = json.loads(json.dumps(resp_json))
        except Exception as e:
            raise Exception(f"Unable to parse reply: {e}") from e

        fault_node = resp_json.get("s:Envelope", {}).get("s:Body", {}).get("s:Fault")
        if fault_node:
            raise Exception(self._parse_fault_node(fault_node))

        try:
            resp_message = check_response(resp_json)
        except Exception as e:
            raise Exception(f"Unable to parse response: {e}") from e

        if not isinstance(resp_message, dict):
            return resp_message

        resp_class = resp_message.get("@ResponseClass", "")
        if resp_class == "Error":
            code = resp_message.get("m:ResponseCode", "Not Specified")
            msg = resp_message.get("m:MessageText", "Not Specified")
            raise Exception(f"API failed. Status code: {code}. Message: {msg}")

        return resp_message

    # Response check functions
    def check_find_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:FindItemResponse"][
            "m:ResponseMessages"
        ]["m:FindItemResponseMessage"]

    def check_getitem_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:GetItemResponse"][
            "m:ResponseMessages"
        ]["m:GetItemResponseMessage"]

    def check_delete_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:DeleteItemResponse"][
            "m:ResponseMessages"
        ]["m:DeleteItemResponseMessage"]

    def check_update_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:UpdateItemResponse"][
            "m:ResponseMessages"
        ]["m:UpdateItemResponseMessage"]

    def check_copy_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:CopyItemResponse"][
            "m:ResponseMessages"
        ]["m:CopyItemResponseMessage"]

    def check_move_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:MoveItemResponse"][
            "m:ResponseMessages"
        ]["m:MoveItemResponseMessage"]

    def check_expand_dl_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:ExpandDLResponse"][
            "m:ResponseMessages"
        ]["m:ExpandDLResponseMessage"]

    def check_findfolder_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:FindFolderResponse"][
            "m:ResponseMessages"
        ]["m:FindFolderResponseMessage"]

    def check_resolve_names_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:ResolveNamesResponse"][
            "m:ResponseMessages"
        ]["m:ResolveNamesResponseMessage"]

    def check_get_attachment_response(self, resp_json):
        return resp_json["s:Envelope"]["s:Body"]["m:GetAttachmentResponse"][
            "m:ResponseMessages"
        ]["m:GetAttachmentResponseMessage"]

    # Folder utilities
    def get_folder_id(
        self, user: str, folder_path: str, is_public_folder: bool = False
    ) -> str | None:
        if not folder_path:
            return None

        folder_path_list = [x.strip() for x in folder_path.split("/") if x.strip()]

        if not folder_path_list:
            return None

        root_folder = "publicfoldersroot" if is_public_folder else "root"

        for i, folder_name in enumerate(folder_path_list):
            if i == 0:
                folder_info = self._get_folder_info(
                    user, folder_name, root_folder, is_public_folder
                )
            else:
                folder_info = self._get_folder_info(
                    user, folder_name, parent_folder_info["id"], is_public_folder
                )

            if not folder_info:
                return None
            parent_folder_info = folder_info

        return parent_folder_info["id"] if parent_folder_info else None

    def _get_folder_info(
        self, user: str, folder_name: str, parent_folder_id: str, is_public_folder: bool
    ) -> dict | None:
        input_xml = ews_soap.xml_get_children_info(user, folder_name, parent_folder_id)

        try:
            resp_json = self.make_rest_call(input_xml, self.check_findfolder_response)
        except Exception:
            return None

        total_items = resp_json.get("m:RootFolder", {}).get("@TotalItemsInView", "0")
        if total_items == "0":
            return None

        folders = resp_json.get("m:RootFolder", {}).get("t:Folders", {}).get("t:Folder")
        if not folders:
            return None

        if not isinstance(folders, list):
            folders = [folders]

        for folder in folders:
            if folder.get("t:DisplayName") == folder_name:
                return {
                    "id": folder["t:FolderId"]["@Id"],
                    "display_name": folder["t:DisplayName"],
                    "children_count": folder.get("t:ChildFolderCount", "0"),
                }

        return {
            "id": folders[0]["t:FolderId"]["@Id"],
            "display_name": folders[0]["t:DisplayName"],
            "children_count": folders[0].get("t:ChildFolderCount", "0"),
        }

    def get_email_based_folder_ids(
        self,
        user: str,
        parent_folder_id: str | None = None,
        is_public_folder: bool = False,
    ) -> list[dict]:
        if parent_folder_id is None:
            parent_folder_id = "publicfoldersroot" if is_public_folder else "root"

        folder_ids = []
        step_size = 500

        for curr_step_value in range(0, 10000, step_size):
            curr_range = f"{curr_step_value}-{curr_step_value + step_size - 1}"
            input_xml = ews_soap.xml_get_children_info(
                user, parent_folder_id=parent_folder_id, query_range=curr_range
            )

            try:
                resp_json = self.make_rest_call(
                    input_xml, self.check_findfolder_response
                )
            except Exception:
                break

            total_items = resp_json.get("m:RootFolder", {}).get(
                "@TotalItemsInView", "0"
            )
            if total_items == "0":
                break

            folders = (
                resp_json.get("m:RootFolder", {}).get("t:Folders", {}).get("t:Folder")
            )
            if not folders:
                break

            if not isinstance(folders, list):
                folders = [folders]

            for folder in folders:
                folder_class = folder.get("t:FolderClass", "")
                if folder_class.startswith("IPF.Note") or folder_class == "":
                    folder_ids.append(
                        {
                            "id": folder["t:FolderId"]["@Id"],
                            "display_name": folder["t:DisplayName"],
                            "children_count": folder.get("t:ChildFolderCount", "0"),
                        }
                    )

            if int(total_items) <= curr_step_value + step_size:
                break

        return folder_ids


def get_string(input_str, charset: str = "utf-8") -> str | None:
    try:
        if input_str:
            return (
                UnicodeDammit(input_str).unicode_markup.encode(charset).decode(charset)
            )
        return None
    except UnicodeDecodeError:
        try:
            if detected := from_bytes(input_str).best():
                return detected.unicode_markup.encode(detected.encoding).decode(
                    detected.encoding
                )
        except Exception:
            pass
        return None


def serialize_complex_fields(resp: dict, fields: list[str]) -> dict:
    for field in fields:
        if field in resp and resp[field] is not None:
            if isinstance(resp[field], dict | list):
                resp[field] = json.dumps(resp[field])
    return resp
