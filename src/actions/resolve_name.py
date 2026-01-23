# Copyright (c) 2016-2026 Splunk Inc.

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from .. import ews_soap
from ..app import Asset, app
from ..helper import EWSHelper


class ResolveNameParams(Params):
    email: str = Param(
        description="Name or Email to resolve",
        required=True,
        cef_types=["exchange alias", "email"],
    )


class ResolvedMailbox(ActionOutput):
    # Mailbox fields
    t_Mailbox_Name: str | None = OutputField(cef_types=["user name"])
    t_Mailbox_EmailAddress: str | None = OutputField(cef_types=["email"])
    t_Mailbox_RoutingType: str | None = None
    t_Mailbox_MailboxType: str | None = None
    # Contact fields
    t_Contact_DisplayName: str | None = None
    t_Contact_GivenName: str | None = None
    t_Contact_Surname: str | None = None
    t_Contact_Initials: str | None = None
    t_Contact_CompanyName: str | None = None
    t_Contact_Department: str | None = None
    t_Contact_JobTitle: str | None = None
    t_Contact_Manager: str | None = None
    t_Contact_AssistantName: str | None = None
    t_Contact_OfficeLocation: str | None = None
    t_Contact_Culture: str | None = None
    t_Contact_ContactSource: str | None = None
    # Complex contact fields (JSON serialized)
    t_Contact_EmailAddresses: str | None = None
    t_Contact_PhoneNumbers: str | None = None
    t_Contact_PhysicalAddresses: str | None = None


class ResolveNameSummary(ActionOutput):
    total_entries: int = 0


def _serialize(val):
    if val is None:
        return None
    if isinstance(val, dict | list):
        return json.dumps(val)
    return str(val) if val else None


@app.action(
    name="lookup email",
    description="Resolve an Alias name or email address, into mailboxes",
    action_type="investigate",
    render_as="table",
)
def resolve_name(
    params: ResolveNameParams, soar: SOARClient, asset: Asset
) -> list[ResolvedMailbox]:
    helper = EWSHelper(asset)

    input_xml = ews_soap.xml_get_resolve_names(params.email)
    resp_json = helper.make_rest_call(input_xml, helper.check_resolve_names_response)

    resolution_set = resp_json.get("m:ResolutionSet", {})
    resolutions = resolution_set.get("t:Resolution", [])

    if isinstance(resolutions, dict):
        resolutions = [resolutions]

    results = []
    for resolution in resolutions:
        mailbox = resolution.get("t:Mailbox", {})
        contact = resolution.get("t:Contact", {})

        result = ResolvedMailbox(
            t_Mailbox_Name=mailbox.get("t:Name"),
            t_Mailbox_EmailAddress=mailbox.get("t:EmailAddress"),
            t_Mailbox_RoutingType=mailbox.get("t:RoutingType"),
            t_Mailbox_MailboxType=mailbox.get("t:MailboxType"),
            t_Contact_DisplayName=contact.get("t:DisplayName"),
            t_Contact_GivenName=contact.get("t:GivenName"),
            t_Contact_Surname=contact.get("t:Surname"),
            t_Contact_Initials=contact.get("t:Initials"),
            t_Contact_CompanyName=contact.get("t:CompanyName"),
            t_Contact_Department=contact.get("t:Department"),
            t_Contact_JobTitle=contact.get("t:JobTitle"),
            t_Contact_Manager=contact.get("t:Manager"),
            t_Contact_AssistantName=contact.get("t:AssistantName"),
            t_Contact_OfficeLocation=contact.get("t:OfficeLocation"),
            t_Contact_Culture=contact.get("t:Culture"),
            t_Contact_ContactSource=contact.get("t:ContactSource"),
            t_Contact_EmailAddresses=_serialize(contact.get("t:EmailAddresses")),
            t_Contact_PhoneNumbers=_serialize(contact.get("t:PhoneNumbers")),
            t_Contact_PhysicalAddresses=_serialize(contact.get("t:PhysicalAddresses")),
        )
        results.append(result)

    soar.set_message(f"Total entries: {len(results)}")
    soar.set_summary(ResolveNameSummary(total_entries=len(results)))
    return results
