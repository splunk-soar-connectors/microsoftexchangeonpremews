# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..helper import EWSHelper


class UpdateEmailParams(Params):
    id: str = Param(
        description="Message ID to update",
        required=True,
        cef_types=["exchange email id"],
    )
    email: str = Param(
        description="Email address of the mailbox owner (used during impersonation)",
        required=False,
        cef_types=["email"],
    )
    subject: str = Param(
        description="Subject to set",
        required=False,
    )
    category: str = Param(
        description="Category to set (comma separated)",
        required=False,
    )


class UpdateEmailOutput(ActionOutput):
    new_change_key: str | None = None


@app.action(
    description="Update an email on the server",
    action_type="generic",
    render_as="table",
)
def update_email(
    params: UpdateEmailParams, soar: SOARClient, asset: Asset
) -> UpdateEmailOutput:
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

    item_id = message.get("t:ItemId", {})
    email_id = item_id.get("@Id")
    change_key = item_id.get("@ChangeKey")

    if not email_id or not change_key:
        raise ValueError("Could not get email ID or change key")

    categories = None
    if params.category:
        categories = [x.strip() for x in params.category.split(",") if x.strip()]

    subject = params.subject if params.subject else None

    if not categories and not subject:
        raise ValueError("At least one of subject or category must be provided")

    update_xml = ews_soap.get_update_email(
        email_id, change_key, categories=categories, subject=subject
    )
    update_resp = helper.make_rest_call(update_xml, helper.check_update_response)

    new_change_key = None
    items = update_resp.get("m:Items", {})
    if items:
        first_item = next(iter(items.values()), {})
        new_change_key = first_item.get("t:ItemId", {}).get("@ChangeKey")

    soar.set_message("Email updated")
    return UpdateEmailOutput(new_change_key=new_change_key)
