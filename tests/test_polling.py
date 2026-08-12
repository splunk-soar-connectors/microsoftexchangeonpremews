# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from lxml import etree

from src import app as ews_app, ews_soap


def test_latest_first_only_descends_for_initial_window() -> None:
    assert ews_app._poll_order("latest first", None) == "Descending"
    assert ews_app._poll_order("latest first", "2026-07-18T00:00:00Z") == "Ascending"
    assert ews_app._poll_order("oldest first", None) == "Ascending"


def test_resume_restriction_includes_checkpoint_boundary() -> None:
    restriction = ews_soap.xml_get_restriction(
        "2026-07-18T00:00:00Z",
        inclusive=True,
    )

    assert b"IsGreaterThanOrEqualTo" in etree.tostring(restriction)


def test_mixed_item_types_are_restored_to_global_timestamp_order() -> None:
    grouped_items = [
        {"id": "new-message", "last_modified": "2026-07-18T03:00:00Z"},
        {"id": "old-message", "last_modified": "2026-07-18T01:00:00Z"},
        {"id": "middle-meeting", "last_modified": "2026-07-18T02:00:00Z"},
    ]

    ordered = ews_app._order_email_ids(grouped_items, "LastModifiedTime", "Ascending")

    assert [item["id"] for item in ordered] == [
        "old-message",
        "middle-meeting",
        "new-message",
    ]


def test_descending_initial_window_preserves_global_order() -> None:
    grouped_items = [
        {"id": "old-message", "created": "2026-07-18T01:00:00Z"},
        {"id": "new-meeting", "created": "2026-07-18T03:00:00Z"},
        {"id": "middle-message", "created": "2026-07-18T02:00:00Z"},
    ]

    ordered = ews_app._order_email_ids(grouped_items, "DateTimeCreated", "Descending")

    assert [item["id"] for item in ordered] == [
        "new-meeting",
        "middle-message",
        "old-message",
    ]
