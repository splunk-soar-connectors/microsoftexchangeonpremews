# Copyright (c) 2026 Splunk Inc.

import base64
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult
from soar_sdk.exceptions import ActionFailure, SoarAPIError

from src.actions.get_email import GetEmailParams, get_email, render_display_email
from src.app import Asset


@pytest.fixture
def message():
    mail = EmailMessage()
    mail["From"] = "sender@example.test"
    mail["To"] = "recipient@example.test"
    mail["Subject"] = "Exchange ingestion"
    mail["Message-ID"] = "<test@example.test>"
    mail.set_content("See https://example.test and contact help@example.test.")
    mail.add_attachment(
        b"\x00\xff",
        maintype="application",
        subtype="octet-stream",
        filename="sample.bin",
    )
    return mail.as_bytes()


@pytest.fixture
def exchange(monkeypatch, message):
    exchange_id = "AQMk-Test"
    mime = base64.b64encode(message).decode()
    result = {
        "t:ItemId": {"@Id": exchange_id, "@ChangeKey": "change-key"},
        "t:Subject": "Exchange ingestion",
        "t:MimeContent": {"#text": mime, "@CharacterSet": "UTF-8"},
    }
    make_rest_call = Mock(return_value={"m:Items": {"t:Message": result}})
    monkeypatch.setattr(
        "src.actions.get_email.EWSHelper.make_rest_call", make_rest_call
    )
    return exchange_id, mime, result, make_rest_call


@pytest.fixture
def soar():
    soar = Mock(spec=SOARClient)
    soar.get_executing_container_id.return_value = 42
    soar.container.create.return_value = 93
    soar.get.return_value = httpx.Response(200, json={"data": {"existing": "value"}})
    soar.post.return_value = httpx.Response(200, json={"success": True})
    soar.vault.create_attachment.side_effect = ["vault-root", "vault-attachment"]
    return soar


@pytest.fixture
def asset():
    fixture_user = "fixture"
    return Asset(
        username=fixture_user, password=fixture_user, add_body_to_header_artifacts=True
    )


def render(params, output, summary):
    result = ActionResult(True, "Email fetched", param=params.model_dump())
    result.add_data(output.model_dump(by_alias=True))
    result.set_summary(summary.model_dump())
    return render_display_email(
        "get_email",
        [({"total_objects": 1, "total_objects_successful": 1}, [result])],
        {
            "QS": {},
            "container": 42,
            "app": 1,
            "no_connection": False,
            "google_maps_key": False,
        },
    )


def test_message_id_ingests_into_current_container(exchange, message, soar, asset):
    message_id, mime, _, request = exchange
    params = GetEmailParams(
        id=message_id, ingest_email=True, use_current_container=True
    )

    output = get_email(params, soar, asset)

    request.assert_called_once()
    soar.container.create.assert_not_called()
    soar.post.assert_called_once_with(
        "/rest/container/42",
        json={"data": {"existing": "value", "raw_email": message.decode()}},
    )
    assert output.t_MimeContent == mime
    assert output.t_ItemId.id == message_id
    assert [call.args for call in soar.vault.create_attachment.call_args_list] == [
        (42, message, "Exchange_ingestion.eml"),
        (42, b"\x00\xff", "sample.bin"),
    ]
    artifacts = [call.args[0] for call in soar.artifact.create.call_args_list]
    assert all(artifact["container_id"] == 42 for artifact in artifacts)
    assert artifacts[0]["cef"]["emailId"] == message_id
    assert "help@example.test" in artifacts[0]["cef"]["emailBody"]
    assert "URL Artifact" in {artifact["name"] for artifact in artifacts}
    assert "Email Address Artifact" in {artifact["name"] for artifact in artifacts}
    assert [artifact["run_automation"] for artifact in artifacts] == [False] * (
        len(artifacts) - 1
    ) + [True]
    summary = soar.set_summary.call_args.args[0]
    assert summary.container_id == 42
    html = render(params, output, summary)
    assert "<td>42</td>" in html
    assert "Ingestion for email was not enabled" not in html


def test_message_id_fetch_only_makes_no_ingestion_calls(exchange, soar, asset):
    message_id, mime, _, _ = exchange
    params = GetEmailParams(
        id=message_id, ingest_email=False, use_current_container=True
    )

    output = get_email(params, soar, asset)

    assert output.t_MimeContent == mime
    soar.container.create.assert_not_called()
    soar.artifact.create.assert_not_called()
    soar.vault.create_attachment.assert_not_called()
    soar.get_executing_container_id.assert_not_called()
    summary = soar.set_summary.call_args.args[0]
    assert summary.container_id is None
    assert "Ingestion for email was not enabled" in render(params, output, summary)


def test_ingest_into_new_container_respects_disabled_extraction(exchange, soar, asset):
    message_id, *_ = exchange
    asset = asset.model_copy(
        update={
            "extract_root_email_as_vault": False,
            "extract_attachments": False,
            "extract_urls": False,
            "extract_ips": False,
            "extract_domains": False,
            "extract_hashes": False,
            "extract_email_addresses": False,
            "add_body_to_header_artifacts": False,
            "save_raw_email_to_container": False,
        }
    )

    get_email(GetEmailParams(id=message_id, ingest_email=True), soar, asset)

    container = soar.container.create.call_args.args[0]
    assert container["source_data_identifier"] == message_id
    assert "data" not in container
    soar.vault.create_attachment.assert_not_called()
    soar.artifact.create.assert_called_once()
    artifact = soar.artifact.create.call_args.args[0]
    assert artifact["container_id"] == 93
    assert "emailBody" not in artifact["cef"]
    assert soar.set_summary.call_args.args[0].container_id == 93


@pytest.mark.parametrize("source", ["container", "vault"])
def test_saved_email_processing_failure_is_reported(
    source, tmp_path, message, soar, asset
):
    if source == "container":
        soar.get.return_value = httpx.Response(
            200,
            json={
                "data": {"raw_email": message.decode()},
                "source_data_identifier": "id",
            },
        )
        params = GetEmailParams(container_id=11, ingest_email=True)
    else:
        path = tmp_path / "email.eml"
        path.write_bytes(message)
        soar.vault.get_attachment.return_value = [SimpleNamespace(open=path.open)]
        params = GetEmailParams(vault_id="existing-vault-id", ingest_email=True)
    soar.vault.create_attachment.side_effect = RuntimeError("Vault unavailable")

    with pytest.raises(RuntimeError, match="Vault unavailable"):
        get_email(params, soar, asset)

    soar.set_summary.assert_not_called()
    soar.set_message.assert_not_called()


@pytest.mark.parametrize(
    "mime, error", [("", "no email MIME"), ("%%%!", "invalid email MIME")]
)
def test_requested_ingestion_requires_valid_mime(exchange, soar, asset, mime, error):
    message_id, _, result, _ = exchange
    result["t:MimeContent"] = {"#text": mime}

    with pytest.raises(ActionFailure, match=error):
        get_email(GetEmailParams(id=message_id, ingest_email=True), soar, asset)

    soar.container.create.assert_not_called()
    soar.set_summary.assert_not_called()


def soar_write_error(payload):
    request = httpx.Request("POST", "https://soar.example.test/rest/artifact")
    response = httpx.Response(400, request=request, json=payload)
    error = SoarAPIError("SOAR write failed")
    error.__cause__ = httpx.HTTPStatusError(
        "Bad Request", request=request, response=response
    )
    return error


def test_ingestion_retry_reuses_existing_artifacts(exchange, soar, asset):
    message_id, *_ = exchange
    soar.container.create.side_effect = soar_write_error({"existing_container_id": 93})
    soar.artifact.create.side_effect = soar_write_error({"existing_artifact_id": 1})
    asset = asset.model_copy(update={"automation_on_duplicate": False})

    get_email(GetEmailParams(id=message_id, ingest_email=True), soar, asset)

    assert soar.artifact.create.call_count > 1
    assert all(
        call.args[0]["container_id"] == 93 and not call.args[0]["run_automation"]
        for call in soar.artifact.create.call_args_list
    )
    assert soar.set_summary.call_args.args[0].container_id == 93


def test_ingestion_surfaces_nonduplicate_artifact_failure(exchange, soar, asset):
    message_id, *_ = exchange
    soar.artifact.create.side_effect = soar_write_error({"message": "request rejected"})

    with pytest.raises(SoarAPIError, match="SOAR write failed"):
        get_email(GetEmailParams(id=message_id, ingest_email=True), soar, asset)

    soar.set_summary.assert_not_called()
