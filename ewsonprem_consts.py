# File: ewsonprem_consts.py
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
EWSONPREM_JSON_DEVICE_URL = "url"
EWSONPREM_JSON_TEST_USER = "test_user"
EWSONPREM_JSON_SUBJECT = "subject"
EWSONPREM_JSON_FROM = "sender"
EWSONPREM_JSON_INT_MSG_ID = "internet_message_id"
EWSONPREM_JSON_EMAIL = "email"
EWSONPREM_JSON_FOLDER = "folder"
EWSONPREM_JSON_BODY = "body"
EWSONPREM_JSON_QUERY = "query"
EWSONPREM_JSON_RANGE = "range"
EWSONPREM_JSON_ID = "id"
EWSONPREM_JSON_GROUP = "group"
EWSONPREM_JSON_INGEST_EMAIL = "ingest_email"
EWS_JSON_CONTAINER_ID = "container_id"
EWS_JSON_VAULT_ID = "vault_id"

EWSONPREM_SEARCH_FINISHED_STATUS = "Finished Searching {0:.0%}"

EWS_JSON_POLL_USER = "poll_user"
EWS_JSON_USE_IMPERSONATE = "use_impersonation"
EWS_JSON_POLL_FOLDER = "poll_folder"
EWS_JSON_INGEST_MANNER = "ingest_manner"
EWS_JSON_INGEST_TIME = "ingest_time"
EWS_JSON_FIRST_RUN_MAX_EMAILS = "first_run_max_emails"
EWS_JSON_POLL_MAX_CONTAINERS = "max_containers"
EWS_JSON_DONT_IMPERSONATE = "dont_impersonate"
EWS_JSON_IMPERSONATE_EMAIL = "impersonate_email"
EWS_JSON_IS_PUBLIC_FOLDER = "is_public_folder"

EWSONPREM_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
EWSONPREM_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
EWSONPREM_ERR_SERVER_CONNECTION = "Connection failed"
EWSONPREM_ERR_FROM_SERVER = "API failed. Status code: {code}. Message: {message}"
EWSONPREM_USING_BASE_URL = "Using url: {base_url}"
EWSONPREM_ERR_VAULT_INFO = "Could not retrieve vault file"
EWSONPREM_ERR_JSON_PARSE = "Unable to parse reply, raw string reply: '{raw_text}'"
EWSONPREM_EXCEPTION_ERR_MESSAGE = "Error Code: {0}. Error Message: {1}"
EWSONPREM_ERR_CODE_MESSAGE = "Error code unavailable"
EWSONPREM_ERR_MESSAGE = "Error message unavailable. Please check the asset configuration and|or action parameters."
TYPE_ERR_MESSAGE = "Error occurred while connecting to the EWS server. Please check the asset configuration and|or the action parameters."
EWSONPREM_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
EWSONPREM_MIME_CONTENT_CONVERSION_ERROR = "Error occurred due to 'Mime-Content' conversion failure"
EWSONPREM_MIME_CONTENT_CONVERSION_MESSAGE = "While getting email data for id {0} 'ErrorMimeContentConversionFailed' error occurred. \
Skipping the email."
EWSONPREM_ERROR_MIME_CONTENT_CONVERSION = 'ErrorMimeContentConversionFailed'

EWSONPREM_MAIL_TYPES = [
    "t:Message",
    "t:MeetingRequest",
    "t:MeetingResponse",
    "t:MeetingMessage",
    "t:MeetingCancellation"
]
EWSONPREM_MAX_END_OFFSET_VAL = 2147483646
EWS_MODIFY_CONFIG = "Toggling the impersonation configuration on the asset might help, or login user does not have privileges to the mailbox."

EWS_INGEST_LATEST_EMAILS = "latest first"
EWS_INGEST_OLDEST_EMAILS = "oldest first"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
