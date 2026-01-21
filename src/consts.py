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

EWSONPREM_MAIL_TYPES = [
    "t:Message",
    "t:MeetingRequest",
    "t:MeetingResponse",
    "t:MeetingMessage",
    "t:MeetingCancellation",
]
EWSONPREM_MAX_END_OFFSET_VAL = 2147483646

EWSONPREM_ERR_SERVER_CONNECTIVITY = "Connection failed"
EWSONPREM_ERR_MIME_CONTENT_CONVERSION = "ErrorMimeContentConversionFailed"
EWSONPREM_MIME_CONTENT_CONVERSION_MESSAGE = (
    "While getting email data for id {0} 'ErrorMimeContentConversionFailed' error occurred. "
    "Skipping the email."
)

EWS_INGEST_LATEST_EMAILS = "latest first"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

DEFAULT_REQUEST_TIMEOUT = 30

EWS_MODIFY_CONFIG = (
    "Toggling the impersonation configuration on the asset might help, "
    "or login user does not have privileges to the mailbox."
)
