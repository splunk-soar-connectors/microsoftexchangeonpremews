# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..consts import EWSONPREM_MAX_END_OFFSET_VAL
from ..helper import EWSHelper


class RunQueryParams(Params):
    email: str = Param(
        description="User's Email (Mailbox to search in)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Folder Name/Path (to search in)",
        required=False,
        default="Inbox",
        cef_types=["mail folder", "mail folder path"],
    )
    subject: str = Param(
        description="Substring to search in Subject",
        required=False,
        default="",
    )
    sender: str = Param(
        description="Sender Email address to match",
        required=False,
        default="",
        cef_types=["email"],
    )
    body: str = Param(
        description="Substring to search in Body",
        required=False,
        default="",
    )
    internet_message_id: str = Param(
        description="Internet Message ID",
        required=False,
        default="",
        cef_types=["internet message id"],
    )
    query: str = Param(
        description="AQS string",
        required=False,
        default="",
    )
    range: str = Param(
        description="Email range to return (min_offset-max_offset)",
        required=False,
        default="0-10",
    )
    ignore_subfolders: bool = Param(
        description="Ignore subfolders",
        required=False,
        default=False,
    )
    is_public_folder: bool = Param(
        description="Mailbox folder is a public folder",
        required=False,
        default=False,
    )


class ItemId(ActionOutput):
    id: str | None = OutputField(alias="@Id", cef_types=["exchange email id"])
    change_key: str | None = OutputField(alias="@ChangeKey")


class Mailbox(ActionOutput):
    t_Name: str | None = OutputField(cef_types=["user name"])
    t_EmailAddress: str | None = OutputField(cef_types=["email"])
    t_MailboxType: str | None = None
    t_RoutingType: str | None = None


class EmailResult(ActionOutput):
    t_Subject: str | None = OutputField(column_name="Subject")
    sender_name: str | None = OutputField(column_name="Sender")
    t_DateTimeReceived: str | None = OutputField(column_name="Received Time")
    folder: str | None = OutputField(column_name="Folder", cef_types=["mail folder"])
    folder_path: str | None = OutputField(
        column_name="Folder Path", cef_types=["mail folder path"]
    )
    t_InternetMessageId: str | None = OutputField(
        column_name="Internet Message ID", cef_types=["internet message id"]
    )
    message_id: str | None = OutputField(
        column_name="Message ID", cef_types=["exchange email id"]
    )
    t_ItemId: ItemId | None = None
    t_Sender: Mailbox | None = None
    t_From: Mailbox | None = None


class RunQuerySummary(ActionOutput):
    emails_matched: int = 0


def _validate_range(email_range: str) -> None:
    try:
        mini, maxi = (int(x) for x in email_range.split("-"))
    except Exception:
        raise ValueError(
            "Unable to parse the range. Please specify the range as min_offset-max_offset"
        ) from None

    if mini < 0 or maxi < 0:
        raise ValueError("Invalid min or max offset value specified in range")

    if mini > maxi:
        raise ValueError("Invalid range value, min_offset greater than max_offset")

    if maxi > EWSONPREM_MAX_END_OFFSET_VAL:
        raise ValueError(
            f"Invalid range value. The max_offset value cannot be greater than {EWSONPREM_MAX_END_OFFSET_VAL}"
        )


@app.action(description="Search emails", action_type="investigate", render_as="table")
def run_query(
    params: RunQueryParams, soar: SOARClient, asset: Asset
) -> list[EmailResult]:
    helper = EWSHelper(asset)

    if asset.use_impersonation:
        helper.set_target_user(params.email)

    _validate_range(params.range)

    if (
        not params.subject
        and not params.sender
        and not params.query
        and not params.body
        and not params.internet_message_id
    ):
        raise ValueError("Please specify at least one search criteria")

    folder_id = helper.get_folder_id(
        params.email, params.folder, params.is_public_folder
    )

    folder_ids = [folder_id] if folder_id else []
    if not folder_ids:
        folder_infos = helper.get_email_based_folder_ids(
            params.email, is_public_folder=params.is_public_folder
        )
        folder_ids = [f["id"] for f in folder_infos]

    results = []

    for fid in folder_ids:
        if params.query:
            input_xml = ews_soap.get_search_request_aqs(
                [fid], params.query, params.range
            )
        else:
            input_xml = ews_soap.get_search_request_filter(
                [fid],
                subject=params.subject or None,
                sender=params.sender or None,
                body=params.body or None,
                int_msg_id=params.internet_message_id or None,
                email_range=params.range,
            )

        try:
            resp_json = helper.make_rest_call(input_xml, helper.check_find_response)
        except Exception:
            continue

        if isinstance(resp_json, list):
            responses = resp_json
        else:
            responses = [resp_json]

        for resp in responses:
            root_folder = resp.get("m:RootFolder", {})
            if not root_folder:
                continue
            items = root_folder.get("t:Items")
            if not items:
                continue

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
                    item_id_data = item.get("t:ItemId", {})
                    sender_data = item.get("t:Sender", {}).get("t:Mailbox", {})
                    from_data = item.get("t:From", {}).get("t:Mailbox", {})

                    item_id = ItemId(
                        id=item_id_data.get("@Id"),
                        change_key=item_id_data.get("@ChangeKey"),
                    )

                    sender = Mailbox(
                        t_Name=sender_data.get("t:Name") or from_data.get("t:Name"),
                        t_EmailAddress=sender_data.get("t:EmailAddress")
                        or from_data.get("t:EmailAddress"),
                        t_MailboxType=sender_data.get("t:MailboxType"),
                        t_RoutingType=sender_data.get("t:RoutingType"),
                    )

                    from_mailbox = Mailbox(
                        t_Name=from_data.get("t:Name"),
                        t_EmailAddress=from_data.get("t:EmailAddress"),
                        t_MailboxType=from_data.get("t:MailboxType"),
                        t_RoutingType=from_data.get("t:RoutingType"),
                    )

                    result = EmailResult(
                        folder=params.folder,
                        folder_path=params.folder,
                        t_DateTimeReceived=item.get("t:DateTimeReceived"),
                        t_Subject=item.get("t:Subject"),
                        t_InternetMessageId=item.get("t:InternetMessageId"),
                        sender_name=sender.t_Name,
                        message_id=item_id.id,
                        t_ItemId=item_id,
                        t_Sender=sender,
                        t_From=from_mailbox,
                    )
                    results.append(result)

    soar.set_message(f"Emails matched: {len(results)}")
    soar.set_summary(RunQuerySummary(emails_matched=len(results)))
    return results
