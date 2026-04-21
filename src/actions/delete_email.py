# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..helper import EWSHelper


class DeleteEmailParams(Params):
    id: str = Param(
        description="Message IDs to delete (comma separated values supported)",
        required=True,
        cef_types=["exchange email id"],
    )
    email: str = Param(
        description="Email of the mailbox owner (used during impersonation)",
        required=False,
        cef_types=["email"],
    )


class DeleteEmailOutput(ActionOutput):
    message_id: str | None = OutputField(
        column_name="Message ID", cef_types=["exchange email id"]
    )
    message: str | None = OutputField(column_name="Status Message")


@app.action(description="Delete emails", action_type="contain", render_as="table")
def delete_email(
    params: DeleteEmailParams, soar: SOARClient, asset: Asset
) -> DeleteEmailOutput:
    helper = EWSHelper(asset)

    if asset.use_impersonation:
        if not params.email:
            raise ValueError("Email is required when impersonation is enabled")
        helper.set_target_user(params.email)

    message_ids = [x.strip() for x in params.id.split(",") if x.strip()]

    if not message_ids:
        raise ValueError("No valid message IDs provided")

    input_xml = ews_soap.get_delete_email(message_ids)
    helper.make_rest_call(input_xml, helper.check_delete_response)

    soar.set_message("Email deleted")
    return DeleteEmailOutput(message_id=params.id, message="Email deleted")
