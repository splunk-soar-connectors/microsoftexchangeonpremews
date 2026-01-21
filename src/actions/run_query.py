# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
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


class EmailResult(ActionOutput):
    t_Subject: str | None = OutputField(column_name="Subject")
    t_Sender_EmailAddress: str | None = OutputField(
        column_name="Sender", cef_types=["email"]
    )
    t_DateTimeReceived: str | None = OutputField(column_name="Received Time")
    folder: str | None = OutputField(column_name="Folder", cef_types=["mail folder"])
    folder_path: str | None = OutputField(
        column_name="Folder Path", cef_types=["mail folder path"]
    )
    t_InternetMessageId: str | None = OutputField(
        column_name="Internet Message ID", cef_types=["internet message id"]
    )
    t_ItemId_Id: str | None = OutputField(
        column_name="Message ID", cef_types=["exchange email id"]
    )
    t_ItemId_ChangeKey: str | None = None
    t_Sender_Name: str | None = OutputField(cef_types=["user name"])
    t_Sender_MailboxType: str | None = None
    t_Sender_RoutingType: str | None = None
    t_From_EmailAddress: str | None = None
    t_From_Name: str | None = OutputField(cef_types=["user name"])
    t_From_MailboxType: str | None = None
    t_From_RoutingType: str | None = None


class RunQuerySummary(ActionOutput):
    emails_matched: int = 0


@app.action(description="Search emails", action_type="investigate", render_as="table")
def run_query(
    params: RunQueryParams, soar: SOARClient, asset: Asset
) -> list[EmailResult]:
    helper = EWSHelper(asset)

    if asset.use_impersonation:
        helper.set_target_user(params.email)

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
                    item_id = item.get("t:ItemId", {})
                    sender = item.get("t:Sender", {}).get("t:Mailbox", {})
                    from_mailbox = item.get("t:From", {}).get("t:Mailbox", {})

                    result = EmailResult(
                        folder=params.folder,
                        folder_path=params.folder,
                        t_DateTimeReceived=item.get("t:DateTimeReceived"),
                        t_Subject=item.get("t:Subject"),
                        t_InternetMessageId=item.get("t:InternetMessageId"),
                        t_ItemId_Id=item_id.get("@Id"),
                        t_ItemId_ChangeKey=item_id.get("@ChangeKey"),
                        t_Sender_Name=sender.get("t:Name")
                        or from_mailbox.get("t:Name"),
                        t_Sender_EmailAddress=sender.get("t:EmailAddress")
                        or from_mailbox.get("t:EmailAddress"),
                        t_Sender_MailboxType=sender.get("t:MailboxType"),
                        t_Sender_RoutingType=sender.get("t:RoutingType"),
                        t_From_EmailAddress=from_mailbox.get("t:EmailAddress"),
                        t_From_Name=from_mailbox.get("t:Name"),
                        t_From_MailboxType=from_mailbox.get("t:MailboxType"),
                        t_From_RoutingType=from_mailbox.get("t:RoutingType"),
                    )
                    results.append(result)

    soar.set_message(f"Emails matched: {len(results)}")
    soar.set_summary(RunQuerySummary(emails_matched=len(results)))
    return results
