# Copyright (c) 2016-2026 Splunk Inc.

import email
import json
import re
from email.header import decode_header, make_header
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..helper import EWSHelper


if TYPE_CHECKING:
    from ..app import Asset


class GetEmailParams(Params):
    id: str = Param(
        description="Message ID to get",
        required=False,
        cef_types=["exchange email id"],
    )
    email: str = Param(
        description="Email of the mailbox owner (used during impersonation)",
        required=False,
        cef_types=["email"],
    )
    container_id: int = Param(
        description="Container ID to get email data from",
        required=False,
        cef_types=["phantom container id"],
    )
    vault_id: str = Param(
        description="Vault ID to get email from",
        required=False,
        cef_types=["vault id"],
    )
    ingest_email: bool = Param(
        description="Create containers and artifacts",
        required=False,
        default=False,
    )
    use_current_container: bool = Param(
        description="Create artifacts in the same container",
        required=False,
        default=False,
    )


class ItemId(ActionOutput):
    id: str | None = OutputField(alias="@Id", cef_types=["exchange email id"])
    change_key: str | None = OutputField(alias="@ChangeKey")


class GetEmailOutput(ActionOutput):
    # Core fields with column display
    t_Subject: str | None = OutputField(column_name="Subject")
    t_DateTimeCreated: str | None = OutputField(column_name="Create Time")
    t_DateTimeSent: str | None = OutputField(column_name="Sent Time")
    t_ItemId: ItemId | None = None

    # Email headers (from container/vault parsing)
    CC: str | None = None
    Content_Language: str | None = None
    Content_Type: str | None = None
    Date: str | None = None
    Delivered_To: str | None = None
    From: str | None = None
    Importance: str | None = None
    MIME_Version: str | None = None
    Message_ID: str | None = OutputField(cef_types=["internet message id"])
    Received: str | None = None
    Return_Path: str | None = None
    Sender: str | None = None
    Subject: str | None = None
    Thread_Index: str | None = None
    Thread_Topic: str | None = None
    To: str | None = None
    X_Mailer: str | None = None
    X_Priority: str | None = None

    # Decoded headers
    decodedBCC: str | None = None
    decodedCC: str | None = None
    decodedFrom: str | None = None
    decodedSubject: str | None = None
    decodedTo: str | None = None

    # EWS response fields
    t_InternetMessageId: str | None = OutputField(cef_types=["internet message id"])
    t_MimeContent: str | None = None
    t_MimeContent_CharacterSet: str | None = None
    t_Body: str | None = None
    t_Body_BodyType: str | None = None
    t_Body_IsTruncated: str | None = None
    t_TextBody: str | None = None
    t_TextBody_BodyType: str | None = None
    t_TextBody_IsTruncated: str | None = None
    t_DateTimeReceived: str | None = None
    t_LastModifiedTime: str | None = None
    t_Size: str | None = None
    t_Sensitivity: str | None = None
    t_HasAttachments: str | None = None
    t_IsRead: str | None = None
    t_IsReadReceiptRequested: str | None = None
    t_IsDeliveryReceiptRequested: str | None = None
    t_IsAssociated: str | None = None
    t_Categories: str | None = None

    # From/Sender mailbox (JSON serialized)
    t_From: str | None = None
    t_Sender: str | None = None

    # Recipients (JSON serialized)
    t_ToRecipients: str | None = None
    t_CcRecipients: str | None = None
    t_BccRecipients: str | None = None

    # Attachments (JSON serialized)
    t_Attachments: str | None = None

    # Meeting-related fields
    t_Start: str | None = None
    t_End: str | None = None
    t_Location: str | None = None
    t_Organizer: str | None = None
    t_RequiredAttendees: str | None = None
    t_OptionalAttendees: str | None = None
    t_MeetingRequestType: str | None = None
    t_ResponseType: str | None = None
    t_IntendedFreeBusyStatus: str | None = None
    t_HasBeenProcessed: str | None = None
    t_IsDelegated: str | None = None
    t_IsOutOfDate: str | None = None
    t_AdjacentMeetingCount: str | None = None
    t_ConflictingMeetingCount: str | None = None
    t_AssociatedCalendarItemId: str | None = None

    # Extended properties (JSON serialized)
    t_ExtendedProperty: str | None = None

    # Response objects (JSON serialized)
    t_ResponseObjects: str | None = None


class GetEmailSummary(ActionOutput):
    subject: str | None = None
    create_time: str | None = None
    sent_time: str | None = None
    container_id: int | None = None


def _decode_email_header(header_value: str) -> str:
    """Decode an email header value handling various encodings."""
    if not header_value:
        return ""
    try:
        decoded = make_header(decode_header(header_value))
        return str(decoded)
    except Exception:
        return header_value


def _get_email_headers_from_mail(mail: email.message.Message) -> CaseInsensitiveDict:
    """Extract headers from an email message object."""
    headers = CaseInsensitiveDict()
    for key in mail.keys():
        headers[key] = mail.get(key)
    return headers


def _add_decoded_headers(headers: CaseInsensitiveDict) -> dict:
    """Add decoded versions of common headers."""
    result = dict(headers)
    for key in ["Subject", "To", "From", "Cc", "Bcc"]:
        if key in headers:
            result[f"decoded{key}"] = _decode_email_header(headers[key])
    return result


def _get_email_from_container(soar: SOARClient, container_id: int) -> tuple[str, str]:
    """Get raw email data from a container."""
    resp = soar.get(f"/rest/container/{container_id}")
    if not resp:
        raise ValueError(f"Container {container_id} not found")

    raw_email = resp.get("data", {}).get("raw_email")
    email_id = resp.get("source_data_identifier", str(container_id))

    if not raw_email:
        raise ValueError("Raw email data not found in container")

    return raw_email, email_id


def _get_email_from_vault(soar: SOARClient, vault_id: str) -> tuple[str, str]:
    """Get raw email data from a vault file."""
    attachments = soar.vault.get_attachment(vault_id=vault_id)
    if not attachments:
        raise ValueError(f"Vault file {vault_id} not found")

    attachment = attachments[0]
    with attachment.open("rb") as f:
        email_bytes = f.read()
    email_data = email_bytes.decode("utf-8", errors="replace")

    return email_data, vault_id


def _handle_email_from_raw_data(
    email_data: str,
    email_id: str,
    soar: SOARClient,
    asset: "Asset",
    ingest_email: bool,
    target_container_id: int | None,
) -> GetEmailOutput:
    """Process raw email data and return output."""
    mail = email.message_from_string(email_data)
    headers = _get_email_headers_from_mail(mail)
    headers_dict = _add_decoded_headers(headers)

    subject = headers_dict.get("decodedSubject") or headers.get("Subject")
    date = headers.get("Date")

    if ingest_email:
        try:
            from soar_sdk.extras.email.processor import (
                EmailProcessor,
                ProcessEmailContext,
            )
            from soar_sdk.shims.phantom.vault import VaultBase

            from ..app import APP_ID

            context = ProcessEmailContext(
                soar=soar,
                vault=VaultBase(soar),
                app_id=APP_ID,
                folder_name="exchange_emails",
                is_hex=True,
            )

            config = {
                "extract_attachments": getattr(asset, "extract_attachments", True),
                "extract_urls": getattr(asset, "extract_urls", True),
                "extract_ips": getattr(asset, "extract_ips", True),
                "extract_domains": getattr(asset, "extract_domains", True),
                "extract_hashes": getattr(asset, "extract_hashes", True),
            }

            processor = EmailProcessor(context, config)
            import time

            processor.process_email(
                base_connector=None,
                rfc822_email=email_data,
                email_id=email_id,
                config=config,
                epoch=time.time(),
                container_id=target_container_id,
            )
        except ImportError:
            pass
        except Exception:
            pass

    summary = GetEmailSummary(
        subject=subject,
        create_time=date,
        sent_time=date,
        container_id=target_container_id,
    )

    soar.set_message(f"Successfully fetched email headers. Subject: {subject}")
    soar.set_summary(summary)

    return GetEmailOutput(
        t_Subject=subject,
        t_DateTimeCreated=date,
        t_DateTimeSent=date,
        t_ItemId=ItemId(id=email_id),
        t_InternetMessageId=headers.get("Message-ID"),
        # Email headers
        CC=headers.get("CC"),
        Content_Language=headers.get("Content-Language"),
        Content_Type=headers.get("Content-Type"),
        Date=date,
        Delivered_To=headers.get("Delivered-To"),
        From=headers.get("From"),
        Importance=headers.get("Importance"),
        MIME_Version=headers.get("MIME-Version"),
        Message_ID=headers.get("Message-ID"),
        Received=headers.get("Received"),
        Return_Path=headers.get("Return-Path"),
        Sender=headers.get("Sender"),
        Subject=headers.get("Subject"),
        Thread_Index=headers.get("Thread-Index"),
        Thread_Topic=headers.get("Thread-Topic"),
        To=headers.get("To"),
        X_Mailer=headers.get("X-Mailer"),
        X_Priority=headers.get("X-Priority"),
        # Decoded headers
        decodedBCC=headers_dict.get("decodedBcc"),
        decodedCC=headers_dict.get("decodedCc"),
        decodedFrom=headers_dict.get("decodedFrom"),
        decodedSubject=headers_dict.get("decodedSubject"),
        decodedTo=headers_dict.get("decodedTo"),
    )


def _clean_email_text(email_text):
    if not email_text:
        return email_text
    email_text = re.sub(r"\r+", "\n", email_text)
    email_text = re.sub(r"\n{3,}", "\n\n", email_text)
    return email_text


def _extract_email_from_json(json_str):
    if not json_str:
        return None
    try:
        data = json.loads(json_str) if isinstance(json_str, str) else json_str
        mailbox = data.get("t:Mailbox", {})
        return mailbox.get("t:EmailAddress")
    except (json.JSONDecodeError, AttributeError):
        return None


def _extract_recipients_from_json(json_str):
    if not json_str:
        return None
    try:
        data = json.loads(json_str) if isinstance(json_str, str) else json_str
        mailboxes = data.get("t:Mailbox", [])
        if isinstance(mailboxes, dict):
            mailboxes = [mailboxes]
        emails = [m.get("t:EmailAddress") for m in mailboxes if m.get("t:EmailAddress")]
        return ", ".join(emails) if emails else None
    except (json.JSONDecodeError, AttributeError):
        return None


def render_display_email(output: list[GetEmailOutput]) -> dict:
    results = []
    for item in output:
        has_headers = any(
            getattr(item, field, None) is not None
            for field in [
                "CC",
                "Content_Type",
                "Date",
                "Delivered_To",
                "From",
                "Message_ID",
                "Received",
                "Return_Path",
                "Sender",
                "Subject",
                "To",
            ]
        )

        is_from_container_or_vault = has_headers and item.t_From is None

        if is_from_container_or_vault:
            header_fields = [
                ("CC", item.CC),
                ("Content-Language", item.Content_Language),
                ("Content-Type", item.Content_Type),
                ("Date", item.Date),
                ("Delivered-To", item.Delivered_To),
                ("From", item.From),
                ("Importance", item.Importance),
                ("MIME-Version", item.MIME_Version),
                ("Message-ID", item.Message_ID),
                ("Received", item.Received),
                ("Return-Path", item.Return_Path),
                ("Sender", item.Sender),
                ("Subject", item.Subject),
                ("Thread-Index", item.Thread_Index),
                ("Thread-Topic", item.Thread_Topic),
                ("To", item.To),
                ("X-Mailer", item.X_Mailer),
                ("X-Priority", item.X_Priority),
            ]
            headers = {k: v for k, v in header_fields if v is not None}

            email_id = item.t_ItemId.id if item.t_ItemId else None
            results.append(
                {
                    "data": True,
                    "source": "headers",
                    "param_container_id": None,
                    "param_vault_id": None,
                    "email_id": email_id,
                    "container_id": None,
                    "ingest_email": False,
                    "headers": headers,
                    "message": None,
                }
            )
        else:
            from_email = _extract_email_from_json(item.t_From)
            sender_email = _extract_email_from_json(item.t_Sender)
            recipients = _extract_recipients_from_json(item.t_ToRecipients)

            email_text = None
            email_body = None
            body = item.t_Body
            if body:
                try:
                    soup = BeautifulSoup(body, "html.parser")
                    email_text = _clean_email_text(soup.get_text())
                except Exception:
                    email_text = None
                if not email_text:
                    email_body = body

            email_id = item.t_ItemId.id if item.t_ItemId else None
            results.append(
                {
                    "data": True,
                    "source": "server",
                    "email_id": email_id,
                    "subject": item.t_Subject,
                    "from_email": from_email,
                    "sender_email": sender_email,
                    "recipients": recipients,
                    "internet_message_id": item.t_InternetMessageId,
                    "create_time": item.t_DateTimeCreated,
                    "sent_time": item.t_DateTimeSent,
                    "container_id": None,
                    "ingest_email": False,
                    "email_text": email_text,
                    "email_body": email_body,
                    "message": None,
                }
            )

    return {"results": results}


def get_email(
    params: GetEmailParams, soar: SOARClient, asset: "Asset"
) -> GetEmailOutput:
    if not params.id and not params.container_id and not params.vault_id:
        raise ValueError("At least one of id, container_id, or vault_id is required")

    target_container_id = None
    if params.use_current_container:
        target_container_id = soar.get_executing_container_id()

    if params.container_id:
        email_data, email_id = _get_email_from_container(soar, params.container_id)
        return _handle_email_from_raw_data(
            email_data, email_id, soar, asset, params.ingest_email, target_container_id
        )

    if params.vault_id:
        email_data, email_id = _get_email_from_vault(soar, params.vault_id)
        return _handle_email_from_raw_data(
            email_data, email_id, soar, asset, params.ingest_email, target_container_id
        )

    helper = EWSHelper(asset)

    if asset.use_impersonation:
        if not params.email:
            raise ValueError("Email is required when impersonation is enabled")
        helper.set_target_user(params.email)

    input_xml = ews_soap.xml_get_emails_data([params.id], asset.version)
    resp_json = helper.make_rest_call(input_xml, helper.check_getitem_response)

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
        raise ValueError("Email not found")

    def _serialize(val):
        if val is None:
            return None
        if isinstance(val, dict | list):
            return json.dumps(val)
        return str(val) if val else None

    subject = message.get("t:Subject")
    create_time = message.get("t:DateTimeCreated")
    sent_time = message.get("t:DateTimeSent")
    internet_msg_id = message.get("t:InternetMessageId")

    mime_content_obj = message.get("t:MimeContent", {})
    mime_content = (
        mime_content_obj.get("#text", "") if isinstance(mime_content_obj, dict) else ""
    )

    body_obj = message.get("t:Body", {})
    body = body_obj.get("#text", "") if isinstance(body_obj, dict) else ""
    body_type = body_obj.get("@BodyType") if isinstance(body_obj, dict) else None
    body_truncated = (
        body_obj.get("@IsTruncated") if isinstance(body_obj, dict) else None
    )

    text_body_obj = message.get("t:TextBody", {})
    text_body = (
        text_body_obj.get("#text", "") if isinstance(text_body_obj, dict) else ""
    )
    text_body_type = (
        text_body_obj.get("@BodyType") if isinstance(text_body_obj, dict) else None
    )
    text_body_truncated = (
        text_body_obj.get("@IsTruncated") if isinstance(text_body_obj, dict) else None
    )

    item_id = message.get("t:ItemId", {})
    email_id = item_id.get("@Id") if isinstance(item_id, dict) else None
    change_key = item_id.get("@ChangeKey") if isinstance(item_id, dict) else None

    summary = GetEmailSummary(
        subject=subject,
        create_time=create_time,
        sent_time=sent_time,
    )

    soar.set_message(
        f"Subject: {subject}, Create time: {create_time}, Sent time: {sent_time}"
    )
    soar.set_summary(summary)

    return GetEmailOutput(
        # Core fields
        t_Subject=subject,
        t_DateTimeCreated=create_time,
        t_DateTimeSent=sent_time,
        t_ItemId=ItemId(id=email_id, change_key=change_key),
        t_InternetMessageId=internet_msg_id,
        # MIME content
        t_MimeContent=mime_content,
        t_MimeContent_CharacterSet=mime_content_obj.get("@CharacterSet")
        if isinstance(mime_content_obj, dict)
        else None,
        # Body
        t_Body=body,
        t_Body_BodyType=body_type,
        t_Body_IsTruncated=body_truncated,
        t_TextBody=text_body,
        t_TextBody_BodyType=text_body_type,
        t_TextBody_IsTruncated=text_body_truncated,
        # Other fields
        t_DateTimeReceived=message.get("t:DateTimeReceived"),
        t_LastModifiedTime=message.get("t:LastModifiedTime"),
        t_Size=message.get("t:Size"),
        t_Sensitivity=message.get("t:Sensitivity"),
        t_HasAttachments=message.get("t:HasAttachments"),
        t_IsRead=message.get("t:IsRead"),
        t_IsReadReceiptRequested=message.get("t:IsReadReceiptRequested"),
        t_IsDeliveryReceiptRequested=message.get("t:IsDeliveryReceiptRequested"),
        t_IsAssociated=message.get("t:IsAssociated"),
        t_Categories=_serialize(message.get("t:Categories")),
        # Sender/From (JSON serialized)
        t_From=_serialize(message.get("t:From")),
        t_Sender=_serialize(message.get("t:Sender")),
        # Recipients (JSON serialized)
        t_ToRecipients=_serialize(message.get("t:ToRecipients")),
        t_CcRecipients=_serialize(message.get("t:CcRecipients")),
        t_BccRecipients=_serialize(message.get("t:BccRecipients")),
        # Attachments (JSON serialized)
        t_Attachments=_serialize(message.get("t:Attachments")),
        # Meeting fields
        t_Start=message.get("t:Start"),
        t_End=message.get("t:End"),
        t_Location=message.get("t:Location"),
        t_Organizer=_serialize(message.get("t:Organizer")),
        t_RequiredAttendees=_serialize(message.get("t:RequiredAttendees")),
        t_OptionalAttendees=_serialize(message.get("t:OptionalAttendees")),
        t_MeetingRequestType=message.get("t:MeetingRequestType"),
        t_ResponseType=message.get("t:ResponseType"),
        t_IntendedFreeBusyStatus=message.get("t:IntendedFreeBusyStatus"),
        t_HasBeenProcessed=message.get("t:HasBeenProcessed"),
        t_IsDelegated=message.get("t:IsDelegated"),
        t_IsOutOfDate=message.get("t:IsOutOfDate"),
        t_AdjacentMeetingCount=message.get("t:AdjacentMeetingCount"),
        t_ConflictingMeetingCount=message.get("t:ConflictingMeetingCount"),
        t_AssociatedCalendarItemId=_serialize(
            message.get("t:AssociatedCalendarItemId")
        ),
        # Extended properties
        t_ExtendedProperty=_serialize(message.get("t:ExtendedProperty")),
        t_ResponseObjects=_serialize(message.get("t:ResponseObjects")),
    )
