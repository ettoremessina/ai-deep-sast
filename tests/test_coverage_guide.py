# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the deep scan coverage tracker."""

import pytest

from coverage_guide import CoverageGuide
from finding_store import FindingStore
from indexer import CodeIndex


PYTHON_SAMPLE = '''\
def func_a():
    pass

def func_b():
    pass
'''

JAVA_SAMPLE = '''\
public class Foo {
    public void bar() {}
}
'''


@pytest.fixture
def store(tmp_path):
    return FindingStore(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def index(tmp_path):
    (tmp_path / "app.py").write_text(PYTHON_SAMPLE)
    (tmp_path / "Foo.java").write_text(JAVA_SAMPLE)
    # min_function_lines=1: these tests exercise coverage tracking, not the
    # trivial-skip feature, and the sample bodies are intentionally short.
    idx = CodeIndex(min_function_lines=1)
    idx.build(str(tmp_path))
    return idx


@pytest.fixture
def guide(index, store):
    return CoverageGuide(index, store)


class TestChecklistGeneration:
    """Tests for coverage checklist generation."""

    def test_generates_per_file_items(self, guide):
        ids = guide.generate_checklist()
        assert len(ids) == 2  # app.py + Foo.java

    def test_includes_custom_goals(self, guide):
        ids = guide.generate_checklist(goals=["Test CSRF protection"])
        assert len(ids) == 3  # 2 files + 1 custom

    def test_empty_index(self, store):
        empty_index = CodeIndex()
        g = CoverageGuide(empty_index, store)
        ids = g.generate_checklist()
        assert len(ids) == 0


class TestCoverageTracking:
    """Tests for coverage progress tracking."""

    def test_not_complete_initially(self, guide):
        guide.generate_checklist()
        assert not guide.is_complete()

    def test_complete_after_closing_all(self, guide, index, tmp_path):
        guide.generate_checklist()

        py_path = str(tmp_path / "app.py")
        java_path = str(tmp_path / "Foo.java")

        guide.mark_file_complete(py_path, "Rule-based + exploratory, 0 findings")
        assert not guide.is_complete()

        guide.mark_file_complete(java_path, "Rule-based + exploratory, 0 findings")
        assert guide.is_complete()

    def test_progress_tracking(self, guide, index, tmp_path):
        guide.generate_checklist()
        progress = guide.get_progress()
        assert progress["total"] == 2
        assert progress["open"] == 2
        assert progress["percent"] == 0.0

        py_path = str(tmp_path / "app.py")
        guide.mark_file_complete(py_path, "Done")
        progress = guide.get_progress()
        assert progress["closed"] == 1
        assert progress["percent"] == 50.0

    def test_mark_nonexistent_file(self, guide):
        guide.generate_checklist()
        result = guide.mark_file_complete("nonexistent.py", "evidence")
        assert result is False


class TestStopDecision:
    """Tests for the should_stop decision (Constitution VI)."""

    def test_no_stop_when_incomplete(self, guide):
        guide.generate_checklist()
        assert not guide.should_stop(yield_below_threshold=True)

    def test_no_stop_without_yield_threshold(self, guide, index, tmp_path):
        guide.generate_checklist()
        for item in guide.store.get_coverage_status()["items"]:
            guide.store.close_coverage_item(item["id"], "Done")
        assert not guide.should_stop(yield_below_threshold=False)

    def test_stop_when_both_conditions_met(self, guide, index, tmp_path):
        guide.generate_checklist()
        for item in guide.store.get_coverage_status()["items"]:
            guide.store.close_coverage_item(item["id"], "Done")
        assert guide.should_stop(yield_below_threshold=True)
