# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..helper import EWSHelper


class ExpandDLParams(Params):
    group: str = Param(
        description="Distribution List to expand",
        required=True,
        cef_types=["email", "exchange distribution list", "user name"],
    )
    recursive: bool = Param(
        description="Expand recursively",
        required=False,
        default=False,
    )


class DLMember(ActionOutput):
    email: str | None = OutputField(column_name="EMAIL", cef_types=["email"])
    user_name: str | None = OutputField(column_name="USER NAME")
    routing_type: str | None = OutputField(column_name="ROUTING TYPE")
    mailbox_type: str | None = OutputField(column_name="MAILBOX TYPE")


class ExpandDLSummary(ActionOutput):
    total_entries: int = 0


@app.action(
    description="Get the email addresses that make up a Distribution List",
    action_type="investigate",
    render_as="table",
)
def list_addresses(
    params: ExpandDLParams, soar: SOARClient, asset: Asset
) -> list[DLMember]:
    helper = EWSHelper(asset)

    all_members = []
    groups_to_expand = [params.group]
    expanded_groups = set()

    while groups_to_expand:
        current_group = groups_to_expand.pop(0)

        if current_group in expanded_groups:
            continue

        expanded_groups.add(current_group)

        input_xml = ews_soap.get_expand_dl(current_group)

        is_initial_group = current_group == params.group
        try:
            resp_json = helper.make_rest_call(
                input_xml, helper.check_expand_dl_response
            )
        except Exception as e:
            if "ErrorNameResolutionNoResults" in str(e):
                if is_initial_group:
                    raise ValueError(
                        f"{e} The input parameter might not be a distribution list."
                    ) from e
                continue
            raise

        dl_expansion = resp_json.get("m:DLExpansion", {})
        mailboxes = dl_expansion.get("t:Mailbox", [])

        if isinstance(mailboxes, dict):
            mailboxes = [mailboxes]

        for mailbox in mailboxes:
            mailbox_type = mailbox.get("t:MailboxType", "")

            member = DLMember(
                user_name=mailbox.get("t:Name"),
                email=mailbox.get("t:EmailAddress"),
                routing_type=mailbox.get("t:RoutingType"),
                mailbox_type=mailbox_type,
            )
            all_members.append(member)

            if params.recursive and mailbox_type in ["PublicDL", "PrivateDL"]:
                email = mailbox.get("t:EmailAddress")
                if email and email not in expanded_groups:
                    groups_to_expand.append(email)

    soar.set_message(f"Total entries: {len(all_members)}")
    soar.set_summary(ExpandDLSummary(total_entries=len(all_members)))
    return all_members
