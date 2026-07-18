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
