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

import email
import hashlib
import importlib.util
import re
from collections.abc import Callable, Generator, Iterator
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.extras.email.processor import HASH_REGEX, IP_REGEX
from soar_sdk.extras.email.rfc5322 import (
    extract_domains_from_urls,
    extract_email_addresses_from_body,
    extract_email_attachments,
    extract_email_body,
    extract_email_headers,
    extract_email_urls,
)
from soar_sdk.extras.email.utils import is_ip
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.models.finding import Finding, FindingAttachment
from soar_sdk.params import OnESPollParams, OnPollParams

from . import ews_soap
from .consts import EWS_INGEST_LATEST_EMAILS
from .helper import EWSHelper


logger = getLogger()


def _load_preprocess_script(script: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Load and return the preprocess_container function from a custom script.

    The script must define a function named 'preprocess_container' that takes
    a container dict and returns a modified container dict.
    """
    if not script or not script.strip():
        return lambda x: x

    try:
        spec = importlib.util.spec_from_loader("preprocess_methods", loader=None)
        module = importlib.util.module_from_spec(spec)
        exec(script, module.__dict__)
    except Exception as e:
        logger.error(f"Error loading custom preprocess script: {e}")
        raise ValueError(f"Error loading custom preprocess script: {e}") from e

    if not hasattr(module, "preprocess_container"):
        raise ValueError("Custom script must define a 'preprocess_container' function")

    return module.preprocess_container


APP_ID = "badc5252-4a82-4a6d-bc53-d1e503857124"


class Asset(BaseAsset):
    # Connectivity fields
    url: str = AssetField(
        required=True,
        description="EWS URL",
        default="https://corp.contoso.com/EWS/Exchange.asmx",
        category=FieldCategory.CONNECTIVITY,
    )
    version: str = AssetField(
        required=False,
        description="EWS Version",
        default="2013",
        value_list=["2013", "2016"],
        category=FieldCategory.CONNECTIVITY,
    )
    verify_server_cert: bool = AssetField(
        required=False,
        description="Verify server certificate",
        default=True,
        category=FieldCategory.CONNECTIVITY,
    )
    username: str = AssetField(
        required=True,
        description="Username",
        category=FieldCategory.CONNECTIVITY,
    )
    password: str = AssetField(
        required=True,
        description="Password",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    poll_user: str = AssetField(
        required=False,
        description="User Email Mailbox (Test Connectivity and Poll)",
        category=FieldCategory.CONNECTIVITY,
    )
    use_impersonation: bool = AssetField(
        required=False,
        description="Use Impersonation",
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )

    # Ingestion fields
    preprocess_script: str = AssetField(
        required=False,
        description="Script with functions to preprocess containers and artifacts",
        default="",
        is_file=True,
        category=FieldCategory.INGEST,
    )
    poll_folder: str = AssetField(
        required=True,
        description="Mailbox folder to be polled",
        default="Inbox",
        category=FieldCategory.INGEST,
    )
    is_public_folder: bool = AssetField(
        required=False,
        description="Mailbox folder is a public folder",
        default=False,
        category=FieldCategory.INGEST,
    )
    first_run_max_emails: int = AssetField(
        required=True,
        description="Maximum emails to poll first time",
        default=2000,
        category=FieldCategory.INGEST,
    )
    max_containers: int = AssetField(
        required=True,
        description="Maximum emails for scheduled polling",
        default=100,
        category=FieldCategory.INGEST,
    )
    ingest_manner: str = AssetField(
        required=True,
        description="How to ingest",
        default="oldest first",
        value_list=["oldest first", "latest first"],
        category=FieldCategory.INGEST,
    )
    container_severity: str = AssetField(
        required=False,
        description="Container Severity",
        default="medium",
        value_list=["low", "medium", "high"],
        category=FieldCategory.INGEST,
    )
    ingest_time: str = AssetField(
        required=False,
        description="Sort mails by",
        default="updated time",
        value_list=["updated time", "created time"],
        category=FieldCategory.INGEST,
    )
    extract_attachments: bool = AssetField(
        required=False,
        description="Extract Attachments",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_urls: bool = AssetField(
        required=False,
        description="Extract URLs",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_ips: bool = AssetField(
        required=False,
        description="Extract IPs",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_domains: bool = AssetField(
        required=False,
        description="Extract Domain Names",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_hashes: bool = AssetField(
        required=False,
        description="Extract Hashes",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_email_addresses: bool = AssetField(
        required=False,
        description="Extract Email Addresses",
        default=True,
        category=FieldCategory.INGEST,
    )
    add_body_to_header_artifacts: bool = AssetField(
        required=False,
        description="Add email body to the Email Artifact",
        default=False,
        category=FieldCategory.INGEST,
    )
    extract_root_email_as_vault: bool = AssetField(
        required=False,
        description="Extract root (primary) email as Vault",
        default=True,
        category=FieldCategory.INGEST,
    )
    save_raw_email_to_container: bool = AssetField(
        required=False,
        description="Save raw email to container data dictionary",
        default=True,
        category=FieldCategory.INGEST,
    )
    automation_on_duplicate: bool = AssetField(
        required=False,
        description="Run automation on duplicate event",
        default=True,
        category=FieldCategory.INGEST,
    )


app = App(
    name="Microsoft Exchange On-Premise EWS",
    app_type="email",
    logo="logo_microsoft.svg",
    logo_dark="logo_microsoft_dark.svg",
    product_vendor="Microsoft",
    product_name="Exchange",
    publisher="Splunk",
    appid=APP_ID,
    fips_compliant=False,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    helper = EWSHelper(asset)

    poll_user = asset.poll_user
    if asset.use_impersonation:
        if not poll_user:
            raise ValueError("Poll user is required when impersonation is enabled")
        helper.set_target_user(poll_user)

    order = (
        "Descending" if asset.ingest_manner == EWS_INGEST_LATEST_EMAILS else "Ascending"
    )
    field_uri = (
        "DateTimeCreated" if asset.ingest_time == "created time" else "LastModifiedTime"
    )

    input_xml = ews_soap.xml_get_email_ids(
        poll_user or asset.username, "inbox", order, 0, 1, None, field_uri
    )

    helper.make_rest_call(input_xml, helper.check_find_response)

    soar.set_message("Test Connectivity Passed")
    logger.info("Test Connectivity Passed")


def _extract_ips_from_text(text: str) -> list[str]:
    """Extract IP addresses from text using SDK utilities."""
    if not text:
        return []
    matches = re.findall(IP_REGEX, text)
    valid_ips = []
    for ip in set(matches):
        if is_ip(ip):
            valid_ips.append(ip)
    return valid_ips


def _extract_hashes_from_text(text: str) -> dict[str, list[str]]:
    """Extract hash values from text using SDK utilities."""
    if not text:
        return {"md5": [], "sha1": [], "sha256": []}
    all_hashes = set(re.findall(HASH_REGEX, text))
    sha256 = [h for h in all_hashes if len(h) == 64]
    sha1 = [h for h in all_hashes if len(h) == 40]
    md5 = [h for h in all_hashes if len(h) == 32]
    return {"md5": md5, "sha1": sha1, "sha256": sha256}


def _extract_iocs_and_attachments(
    mime_content: str,
    email_id: str,
    asset: Asset,
    soar: SOARClient,
) -> Iterator[Artifact]:
    """Extract IOCs and attachments from email MIME content."""
    try:
        mail = email.message_from_string(mime_content)
    except Exception as e:
        logger.warning(f"Failed to parse MIME content for {email_id}: {e}")
        return

    body = extract_email_body(mail)
    body_text = (body.plain_text or "") + (body.html or "")

    if asset.extract_urls:
        urls = extract_email_urls(mail)
        for url in urls:
            yield Artifact(
                name="URL Artifact",
                label="url",
                severity=asset.container_severity,
                cef={"requestURL": url},
                cef_types={"requestURL": ["url"]},
            )

    if asset.extract_domains:
        urls = extract_email_urls(mail)
        domains = extract_domains_from_urls(urls)
        for domain in domains:
            yield Artifact(
                name="Domain Artifact",
                label="domain",
                severity=asset.container_severity,
                cef={"destinationDnsDomain": domain},
                cef_types={"destinationDnsDomain": ["domain"]},
            )

    if asset.extract_ips:
        ips = _extract_ips_from_text(body_text)
        headers = extract_email_headers(mail)
        for received in headers.received:
            ips.extend(_extract_ips_from_text(received))
        for ip in set(ips):
            yield Artifact(
                name="IP Artifact",
                label="ip",
                severity=asset.container_severity,
                cef={"destinationAddress": ip},
                cef_types={"destinationAddress": ["ip"]},
            )

    if asset.extract_hashes:
        hashes = _extract_hashes_from_text(body_text)
        for md5 in hashes["md5"]:
            yield Artifact(
                name="Hash Artifact",
                label="hash",
                severity=asset.container_severity,
                cef={"fileHashMd5": md5},
                cef_types={"fileHashMd5": ["hash", "md5"]},
            )
        for sha1 in hashes["sha1"]:
            yield Artifact(
                name="Hash Artifact",
                label="hash",
                severity=asset.container_severity,
                cef={"fileHashSha1": sha1},
                cef_types={"fileHashSha1": ["hash", "sha1"]},
            )
        for sha256 in hashes["sha256"]:
            yield Artifact(
                name="Hash Artifact",
                label="hash",
                severity=asset.container_severity,
                cef={"fileHashSha256": sha256},
                cef_types={"fileHashSha256": ["hash", "sha256"]},
            )

    if asset.extract_email_addresses:
        addresses = extract_email_addresses_from_body(mail)
        for addr in addresses:
            yield Artifact(
                name="Email Address Artifact",
                label="email",
                severity=asset.container_severity,
                cef={"emailAddress": addr},
                cef_types={"emailAddress": ["email"]},
            )

    if asset.extract_attachments:
        attachments = extract_email_attachments(mail, include_content=True)
        for att in attachments:
            if not att.content:
                continue
            try:
                file_hash = hashlib.sha256(att.content).hexdigest()
                vault_info = soar.vault.add(
                    file_content=att.content,
                    file_name=att.filename,
                    container_id=None,
                )
                if vault_info:
                    yield Artifact(
                        name="Vault Artifact",
                        label="vault",
                        severity=asset.container_severity,
                        cef={
                            "vaultId": vault_info.vault_id
                            if hasattr(vault_info, "vault_id")
                            else str(vault_info),
                            "fileName": att.filename,
                            "fileSize": att.size,
                            "fileHashSha256": file_hash,
                        },
                        cef_types={
                            "vaultId": ["vault id"],
                            "fileName": ["file name"],
                            "fileHashSha256": ["hash", "sha256"],
                        },
                    )
            except Exception as e:
                logger.warning(
                    f"Failed to save attachment {att.filename} to vault: {e}"
                )


def _get_email_mime_content(
    helper: EWSHelper, email_id: str, version: str
) -> tuple[str | None, dict]:
    """Fetch full MIME content for an email."""
    import base64

    input_xml = ews_soap.xml_get_emails_data([email_id], version)
    try:
        resp_json = helper.make_rest_call(input_xml, helper.check_getitem_response)
    except Exception as e:
        logger.warning(f"Failed to get email content for {email_id}: {e}")
        return None, {}

    if isinstance(resp_json, list):
        resp_json = resp_json[0] if resp_json else {}

    items = resp_json.get("m:Items", {})
    message = None
    for mail_type in [
        "t:Message",
        "t:MeetingRequest",
        "t:MeetingResponse",
        "t:MeetingMessage",
        "t:MeetingCancellation",
    ]:
        if mail_type in items:
            message = items[mail_type]
            break

    if not message:
        return None, {}

    mime_b64 = message.get("t:MimeContent", {}).get("#text", "")
    if mime_b64:
        try:
            mime_content = base64.b64decode(mime_b64).decode("utf-8", errors="replace")
        except Exception:
            mime_content = None
    else:
        mime_content = None

    email_data = {
        "subject": message.get("t:Subject"),
        "from": message.get("t:From", {}).get("t:Mailbox", {}).get("t:EmailAddress"),
        "date_created": message.get("t:DateTimeCreated"),
        "date_sent": message.get("t:DateTimeSent"),
        "internet_message_id": message.get("t:InternetMessageId"),
        "body": message.get("t:Body", {}).get("#text", ""),
    }

    return mime_content, email_data


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    helper = EWSHelper(asset)

    poll_user = asset.poll_user
    if not poll_user:
        raise ValueError("Poll user is required for polling")

    if asset.use_impersonation:
        helper.set_target_user(poll_user)

    preprocess_fn = _load_preprocess_script(asset.preprocess_script)

    state = dict(asset.ingest_state.get_all()) if hasattr(asset, "ingest_state") else {}

    is_poll_now = params.is_manual_poll()
    if is_poll_now:
        max_emails = params.container_count if params.container_count > 0 else 100
        last_time = None
    else:
        is_first_run = state.get("first_run", True)
        max_emails = (
            asset.first_run_max_emails if is_first_run else asset.max_containers
        )
        last_time = state.get("last_time")

    order = (
        "Descending" if asset.ingest_manner == EWS_INGEST_LATEST_EMAILS else "Ascending"
    )
    field_uri = (
        "DateTimeCreated" if asset.ingest_time == "created time" else "LastModifiedTime"
    )

    folder_id = helper.get_folder_id(
        poll_user, asset.poll_folder, asset.is_public_folder
    )
    if not folder_id:
        folder_id = "inbox"

    restriction = None
    if last_time and not is_poll_now:
        restriction = ews_soap.xml_get_restriction(last_time, field_uri=field_uri)

    input_xml = ews_soap.xml_get_email_ids(
        poll_user, folder_id, order, 0, max_emails, restriction, field_uri
    )

    try:
        resp_json = helper.make_rest_call(input_xml, helper.check_find_response)
    except Exception as e:
        logger.error(f"Error polling emails: {e}")
        raise

    root_folder = resp_json.get("m:RootFolder", {})
    items = root_folder.get("t:Items", {})

    email_ids = []
    for mail_type in [
        "t:Message",
        "t:MeetingRequest",
        "t:MeetingResponse",
        "t:MeetingMessage",
        "t:MeetingCancellation",
    ]:
        mail_items = items.get(mail_type, [])
        if isinstance(mail_items, dict):
            mail_items = [mail_items]
        for item in mail_items:
            item_id = item.get("t:ItemId", {}).get("@Id")
            if item_id:
                email_ids.append(
                    {
                        "id": item_id,
                        "last_modified": item.get("t:LastModifiedTime"),
                        "created": item.get("t:DateTimeCreated"),
                    }
                )

    latest_time = last_time
    emails_processed = 0

    for email_info in email_ids:
        if emails_processed >= max_emails:
            break

        email_id = email_info["id"]
        email_time = (
            email_info.get("last_modified")
            if field_uri == "LastModifiedTime"
            else email_info.get("created")
        )
        if email_time and (not latest_time or email_time > latest_time):
            latest_time = email_time

        mime_content, email_data = _get_email_mime_content(
            helper, email_id, asset.version
        )

        subject = email_data.get("subject") or f"Email {email_id[:30]}..."
        container_name = (
            f"{subject[:100]}" if subject else f"Email ID: {email_id[:50]}..."
        )

        container_dict = {
            "name": container_name,
            "source_data_identifier": email_id,
            "severity": asset.container_severity,
            "data": {
                "raw_email": mime_content,
                "subject": email_data.get("subject"),
                "from": email_data.get("from"),
                "date_created": email_data.get("date_created"),
                "date_sent": email_data.get("date_sent"),
                "internet_message_id": email_data.get("internet_message_id"),
            }
            if asset.save_raw_email_to_container
            else None,
            "artifacts": [],
        }

        cef = {
            "emailId": email_id,
            "fromEmail": email_data.get("from"),
            "emailSubject": email_data.get("subject"),
            "lastModifiedTime": email_info.get("last_modified"),
            "dateTimeCreated": email_info.get("created"),
            "internetMessageId": email_data.get("internet_message_id"),
        }

        if asset.add_body_to_header_artifacts and email_data.get("body"):
            cef["emailBody"] = email_data.get("body")

        container_dict["artifacts"].append(
            {
                "name": "Email Artifact",
                "label": "email",
                "severity": asset.container_severity,
                "cef": cef,
                "cef_types": {
                    "fromEmail": ["email"],
                    "emailId": ["exchange email id"],
                    "internetMessageId": ["internet message id"],
                },
            }
        )

        if asset.preprocess_script:
            try:
                container_dict = preprocess_fn(container_dict)
            except Exception as e:
                logger.warning(f"Preprocess script error for email {email_id}: {e}")

        container = Container(
            name=container_dict.get("name", container_name),
            source_data_identifier=container_dict.get(
                "source_data_identifier", email_id
            ),
            severity=container_dict.get("severity", asset.container_severity),
            data=container_dict.get("data"),
        )
        yield container

        for art_dict in container_dict.get("artifacts", []):
            artifact = Artifact(
                name=art_dict.get("name", "Artifact"),
                label=art_dict.get("label", "artifact"),
                severity=art_dict.get("severity", asset.container_severity),
                cef=art_dict.get("cef", {}),
                cef_types=art_dict.get("cef_types", {}),
            )
            yield artifact

        if mime_content:
            yield from _extract_iocs_and_attachments(
                mime_content, email_id, asset, soar
            )

        emails_processed += 1

    if not is_poll_now and latest_time:
        state["last_time"] = latest_time
        state["first_run"] = False
        if hasattr(asset, "ingest_state"):
            asset.ingest_state.put_all(state)

    logger.info(f"Processed {emails_processed} emails")


@app.on_es_poll()
def on_es_poll(
    params: OnESPollParams, soar: SOARClient, asset: Asset
) -> Generator[Finding, int | None]:
    """Poll for new emails and create ES findings for each email."""
    helper = EWSHelper(asset)

    poll_user = asset.poll_user
    if not poll_user:
        raise ValueError("Poll user is required for ES polling")

    if asset.use_impersonation:
        helper.set_target_user(poll_user)

    state = dict(asset.ingest_state.get_all()) if hasattr(asset, "ingest_state") else {}

    is_first_run = state.get("es_first_run", True)
    max_emails = asset.first_run_max_emails if is_first_run else asset.max_containers
    last_time = state.get("es_last_time")

    order = (
        "Descending" if asset.ingest_manner == EWS_INGEST_LATEST_EMAILS else "Ascending"
    )
    field_uri = (
        "DateTimeCreated" if asset.ingest_time == "created time" else "LastModifiedTime"
    )

    folder_id = helper.get_folder_id(
        poll_user, asset.poll_folder, asset.is_public_folder
    )
    if not folder_id:
        folder_id = "inbox"

    restriction = None
    if last_time:
        restriction = ews_soap.xml_get_restriction(last_time, field_uri=field_uri)

    input_xml = ews_soap.xml_get_email_ids(
        poll_user, folder_id, order, 0, max_emails, restriction, field_uri
    )

    try:
        resp_json = helper.make_rest_call(input_xml, helper.check_find_response)
    except Exception as e:
        logger.error(f"Error polling emails for ES: {e}")
        raise

    root_folder = resp_json.get("m:RootFolder", {})
    items = root_folder.get("t:Items", {})

    email_ids = []
    for mail_type in [
        "t:Message",
        "t:MeetingRequest",
        "t:MeetingResponse",
        "t:MeetingMessage",
        "t:MeetingCancellation",
    ]:
        mail_items = items.get(mail_type, [])
        if isinstance(mail_items, dict):
            mail_items = [mail_items]
        for item in mail_items:
            item_id = item.get("t:ItemId", {}).get("@Id")
            if item_id:
                email_ids.append(
                    {
                        "id": item_id,
                        "last_modified": item.get("t:LastModifiedTime"),
                        "created": item.get("t:DateTimeCreated"),
                    }
                )

    latest_time = last_time
    emails_processed = 0

    for email_info in email_ids:
        if emails_processed >= max_emails:
            break

        email_id = email_info["id"]
        email_time = (
            email_info.get("last_modified")
            if field_uri == "LastModifiedTime"
            else email_info.get("created")
        )
        if email_time and (not latest_time or email_time > latest_time):
            latest_time = email_time

        mime_content, email_data = _get_email_mime_content(
            helper, email_id, asset.version
        )

        subject = email_data.get("subject") or f"Email {email_id[:30]}..."

        attachments = []
        if mime_content:
            attachments.append(
                FindingAttachment(
                    file_name=f"email_{email_id[:30]}.eml",
                    data=mime_content.encode("utf-8")
                    if isinstance(mime_content, str)
                    else mime_content,
                )
            )

        yield Finding(
            rule_title=f"Email: {subject[:100]}"
            if subject
            else f"Email ID: {email_id[:50]}",
            attachments=attachments if attachments else None,
        )

        emails_processed += 1

    if latest_time:
        state["es_last_time"] = latest_time
        state["es_first_run"] = False
        if hasattr(asset, "ingest_state"):
            asset.ingest_state.put_all(state)

    logger.info(f"Processed {emails_processed} emails for ES findings")


# Import action modules to register them with the app
from .actions import (  # noqa: F401
    copy_email,
    delete_email,
    expand_dl,
    get_email,
    move_email,
    resolve_name,
    run_query,
    update_email,
)


if __name__ == "__main__":
    app.cli()
