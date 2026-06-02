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
from urllib.parse import urlsplit, urlunsplit

import requests
from requests_ntlm import HttpNtlmAuth
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app
from ..consts import DEFAULT_REQUEST_TIMEOUT


logger = getLogger()


class EWSMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "EWS endpoint to call, appended to the asset URL's host. "
            "Leave blank to call the asset URL as-is (e.g. 'EWS/Exchange.asmx'). "
            "Example: 'EWS/Exchange.asmx' or 'autodiscover/autodiscover.xml'"
        ),
        required=False,
        default="",
    )
    verify_ssl: bool | None = Param(
        description="Whether to verify the SSL certificate. Defaults to the asset's 'Verify server certificate' setting.",
        required=False,
        default=None,
    )


class EWSMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=["<s:Envelope>...</s:Envelope>"])

    @classmethod
    def from_response(cls, response: requests.Response) -> "EWSMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


@app.make_request()
def http_action(params: EWSMakeRequestParams, asset: Asset) -> EWSMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    if params.endpoint:
        parts = urlsplit(asset.url)
        endpoint = params.endpoint.lstrip("/")
        url = urlunsplit((parts.scheme, parts.netloc, f"/{endpoint}", "", ""))
    else:
        url = asset.url

    username = asset.username.replace("/", "\\")
    auth = HttpNtlmAuth(username, asset.password)

    headers: dict = {
        "Content-Type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
    }

    if params.headers:
        try:
            headers.update(json.loads(params.headers))
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

    body = None
    json_body = None
    if params.body:
        content_type = headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                json_body = json.loads(params.body)
            except (json.JSONDecodeError, TypeError) as e:
                raise ActionFailure(f"Invalid JSON body: {params.body}") from e
        else:
            body = params.body

    timeout = params.timeout or DEFAULT_REQUEST_TIMEOUT
    verify = (
        params.verify_ssl if params.verify_ssl is not None else asset.verify_server_cert
    )

    try:
        response = requests.request(
            method=params.http_method,
            url=url,
            auth=auth,
            headers=headers,
            params=query_params,
            data=body,
            json=json_body,
            timeout=timeout,
            verify=verify,
        )
    except Exception as e:
        raise ActionFailure(f"Request failed: {e}") from e

    return EWSMakeRequestOutput.from_response(response)
