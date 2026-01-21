# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..helper import EWSHelper


class MoveEmailParams(Params):
    id: str = Param(
        description="Message ID to move",
        required=True,
        cef_types=["exchange email id"],
    )
    email: str = Param(
        description="Destination Mailbox (Email)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Destination Mail Folder Name/Path",
        required=True,
        cef_types=["mail folder", "mail folder path"],
    )
    impersonate_email: str = Param(
        description="Impersonation Email",
        required=False,
        cef_types=["email"],
    )
    dont_impersonate: bool = Param(
        description="Don't use impersonation",
        required=False,
        default=False,
    )
    is_public_folder: bool = Param(
        description="Mailbox folder is a public folder",
        required=False,
        default=False,
    )


class MoveEmailOutput(ActionOutput):
    user_email: str | None = OutputField(column_name="User Email", cef_types=["email"])
    folder: str | None = OutputField(column_name="Folder")
    source_email_id: str | None = OutputField(
        column_name="Source Message ID", cef_types=["exchange email id"]
    )
    new_email_id: str | None = OutputField(
        column_name="Destination Message ID", cef_types=["exchange email id"]
    )
    status_message: str | None = OutputField(column_name="Status Message")


@app.action(
    description="Move an email to a folder", action_type="generic", render_as="table"
)
def move_email(
    params: MoveEmailParams, soar: SOARClient, asset: Asset
) -> MoveEmailOutput:
    helper = EWSHelper(asset)

    use_impersonation = asset.use_impersonation and not params.dont_impersonate

    if use_impersonation:
        target_user = params.impersonate_email or params.email
        helper.set_target_user(target_user)

    folder_id = helper.get_folder_id(
        params.email, params.folder, params.is_public_folder
    )
    if not folder_id:
        raise ValueError(f"Could not find folder: {params.folder}")

    input_xml = ews_soap.get_move_email(params.id, folder_id)
    resp_json = helper.make_rest_call(input_xml, helper.check_move_response)

    new_email_id = None
    items = resp_json.get("m:Items", {})
    message = items.get("t:Message", {})
    if message:
        new_email_id = message.get("t:ItemId", {}).get("@Id")

    soar.set_message("Email moved")
    return MoveEmailOutput(
        user_email=params.email,
        folder=params.folder,
        source_email_id=params.id,
        new_email_id=new_email_id,
        status_message="Email moved successfully"
        if new_email_id
        else "Email move completed",
    )
