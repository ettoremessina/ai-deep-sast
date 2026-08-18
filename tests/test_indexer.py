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

"""Tests for the code indexer (tree-sitter based code index)."""

import json
import os

import pytest

from indexer import CodeIndex, FunctionInfo, TreeSitterParser


# --- Test fixtures ---

PYTHON_SAMPLE = '''\
import os

def read_config(path):
    with open(path) as f:
        return f.read()

def validate_input(user_input):
    if not user_input:
        raise ValueError("empty input")
    return sanitize(user_input)

def sanitize(text):
    return text.strip()

class AuthHandler:
    def login(self, username, password):
        config = read_config("/etc/app.conf")
        if self.check_password(username, password):
            return True
        return False

    def check_password(self, username, password):
        return password == "admin"
'''

JAVA_SAMPLE = '''\
package com.example;

public class UserService {
    public User getUser(String id) {
        return database.findById(id);
    }

    public void createUser(String name, String email) {
        User user = new User(name, email);
        database.save(user);
        notifyAdmin(user);
    }

    private void notifyAdmin(User user) {
        emailService.send("admin@example.com", user.toString());
    }
}
'''

JS_SAMPLE = '''\
function fetchData(url) {
    return fetch(url).then(res => res.json());
}

function processData(data) {
    const cleaned = sanitize(data);
    return transform(cleaned);
}

function sanitize(input) {
    return input.trim();
}
'''


REACT_JSX_SAMPLE = '''import React, { useState, useCallback } from 'react';

const Profile = ({ user }) => {
    const [bio, setBio] = useState(user.bio);

    const handleSave = useCallback(async () => {
        const token = "sk_live_hardcoded_secret_123456";
        await fetch(`/api/users/${user.id}`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
        });
    }, [bio, user.id]);

    return (
        <div>
            <div dangerouslySetInnerHTML={{ __html: bio }} />
            <button onClick={() => handleSave()}>Save</button>
        </div>
    );
};

function renderRaw(html) {
    document.getElementById('x').innerHTML = html;
}

export default Profile;
'''

REACT_TSX_SAMPLE = '''import React from 'react';

interface Props { html: string; }

export function Widget({ html }: Props) {
    const apiKey: string = "AKIAIOSFODNN7EXAMPLE";
    function doThing(v: string) {
        document.getElementById('t')!.innerHTML = v + apiKey;
    }
    return <div onClick={() => doThing(html)}>{html}</div>;
}

export class Old extends React.Component<Props> {
    unsafeRun() { eval(this.props.html); }
    render() { return <span/>; }
}
'''

BROKEN_TS_SAMPLE = '''export function halfWritten(a: string) {
    return a.
'''

TWO_COMPONENTS_SAMPLE = '''\
const A = () => {
    const onSubmit = () => { fetch('/a'); };
    return null;
};
const B = () => {
    const onSubmit = () => { fetch('/b'); };
    return null;
};
'''

MJS_SAMPLE = 'export function fromMjs() { return 1; }\n'

MTS_SAMPLE = 'export function fromMts(): number { return 1; }\n'


@pytest.fixture
def python_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(PYTHON_SAMPLE)
    return str(f)


@pytest.fixture
def java_file(tmp_path):
    f = tmp_path / "UserService.java"
    f.write_text(JAVA_SAMPLE)
    return str(f)


@pytest.fixture
def js_file(tmp_path):
    f = tmp_path / "utils.js"
    f.write_text(JS_SAMPLE)
    return str(f)


@pytest.fixture
def jsx_file(tmp_path):
    f = tmp_path / "Profile.jsx"
    f.write_text(REACT_JSX_SAMPLE)
    return str(f)


@pytest.fixture
def tsx_file(tmp_path):
    f = tmp_path / "Widget.tsx"
    f.write_text(REACT_TSX_SAMPLE)
    return str(f)


@pytest.fixture
def multi_lang_dir(tmp_path):
    (tmp_path / "app.py").write_text(PYTHON_SAMPLE)
    (tmp_path / "UserService.java").write_text(JAVA_SAMPLE)
    (tmp_path / "utils.js").write_text(JS_SAMPLE)
    (tmp_path / "README.md").write_text("# Not code")
    return str(tmp_path)


@pytest.fixture
def index():
    return CodeIndex()


# --- TreeSitterParser ---

class TestParser:
    """Tests for the tree-sitter parser."""

    def test_parse_python_functions(self, python_file):
        parser = TreeSitterParser()
        functions, calls = parser.parse_file(python_file)
        names = [f.name for f in functions]
        assert "read_config" in names
        assert "validate_input" in names
        assert "sanitize" in names
        assert "login" in names
        assert "check_password" in names

    def test_parse_python_class_methods(self, python_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(python_file)
        login = next(f for f in functions if f.name == "login")
        assert login.class_name == "AuthHandler"
        assert login.qualified_name == "AuthHandler.login"

    def test_parse_python_calls(self, python_file):
        parser = TreeSitterParser()
        _, calls = parser.parse_file(python_file)
        callee_names = [c[1] for c in calls]
        assert "sanitize" in callee_names
        assert "read_config" in callee_names

    def test_parse_java_methods(self, java_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(java_file)
        names = [f.name for f in functions]
        assert "getUser" in names
        assert "createUser" in names
        assert "notifyAdmin" in names

    def test_parse_java_class_name(self, java_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(java_file)
        for func in functions:
            assert func.class_name == "UserService"

    def test_parse_javascript_functions(self, js_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(js_file)
        names = [f.name for f in functions]
        assert "fetchData" in names
        assert "processData" in names
        assert "sanitize" in names

    def test_parse_unsupported_extension(self, tmp_path):
        f = tmp_path / "readme.txt"
        f.write_text("not code")
        parser = TreeSitterParser()
        functions, calls = parser.parse_file(str(f))
        assert functions == []
        assert calls == []

    def test_function_body_content(self, python_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(python_file)
        sanitize = next(f for f in functions if f.name == "sanitize" and f.class_name is None)
        assert "return text.strip()" in sanitize.body

    def test_function_line_numbers(self, python_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(python_file)
        read_config = next(f for f in functions if f.name == "read_config")
        assert read_config.start_line == 3
        assert read_config.end_line == 5


# --- CodeIndex build ---

class TestIndexBuild:
    """Tests for building the code index."""

    def test_build_single_file(self, index, python_file):
        stats = index.build(python_file)
        assert stats["files_parsed"] == 1
        assert stats["functions_found"] >= 5
        assert stats["errors"] == 0
        assert index.is_queryable

    def test_build_directory(self, index, multi_lang_dir):
        stats = index.build(multi_lang_dir)
        assert stats["files_parsed"] == 3
        assert stats["functions_found"] >= 10
        assert index.is_queryable

    def test_build_excludes_non_code(self, index, multi_lang_dir):
        stats = index.build(multi_lang_dir)
        all_funcs = index.get_all_functions()
        files = {f["file_path"] for f in all_funcs}
        assert not any(f.endswith(".md") for f in files)

    def test_build_empty_directory(self, index, tmp_path):
        stats = index.build(str(tmp_path))
        assert stats["files_parsed"] == 0
        assert not index.is_queryable

    def test_incremental_build(self, index, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("def foo(): pass")
        index.build(str(tmp_path))
        assert index.get_stats()["total_functions"] == 1

        # Second build of unchanged file should skip
        stats = index.build(str(tmp_path))
        assert stats["files_skipped"] == 1
        assert stats["files_parsed"] == 0

    def test_incremental_reindex_on_change(self, index, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("def foo(): pass")
        index.build(str(tmp_path))
        assert index.get_stats()["total_functions"] == 1

        f.write_text("def foo(): pass\ndef bar(): pass")
        stats = index.build(str(tmp_path))
        assert stats["files_parsed"] == 1
        assert index.get_stats()["total_functions"] == 2

    def test_build_graceful_on_parse_error(self, index, tmp_path):
        f = tmp_path / "bad.py"
        f.write_bytes(b"\x80\x81\x82 invalid utf-8 mixed with def foo(): pass")
        stats = index.build(str(tmp_path))
        assert stats["errors"] == 0  # tree-sitter handles bad input gracefully


# --- React / JSX / TSX coverage ---

class TestReactParsing:
    """Tests for JSX/TSX parsing and named-arrow-function extraction."""

    def test_tsx_uses_jsx_grammar(self, tsx_file):
        """A .tsx file must parse without syntax errors (needs the TSX grammar)."""
        parser = TreeSitterParser()
        parser.parse_file(tsx_file)
        assert parser.syntax_error_files == []

    def test_tsx_function_component_found(self, tsx_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(tsx_file)
        names = {f.name for f in functions}
        assert "Widget" in names
        assert "doThing" in names

    def test_tsx_class_component_methods_found(self, tsx_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(tsx_file)
        by_qname = {f.qualified_name for f in functions}
        assert "Old.unsafeRun" in by_qname
        assert "Old.render" in by_qname

    def test_arrow_component_indexed(self, jsx_file):
        """const Foo = () => {} must be indexed under the name Foo."""
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(jsx_file)
        names = {f.name for f in functions}
        assert "Profile" in names
        assert "renderRaw" in names

    def test_arrow_component_body_complete(self, jsx_file):
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(jsx_file)
        profile = next(f for f in functions if f.name == "Profile")
        assert "dangerouslySetInnerHTML" in profile.body
        assert "sk_live_hardcoded_secret" in profile.body

    def test_arrow_wrapped_in_hook_indexed(self, jsx_file):
        """useCallback(() => {}) must be indexed under the variable name."""
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(jsx_file)
        names = {f.name for f in functions}
        assert "handleSave" in names

    def test_derived_name_qualified_by_enclosing_function(self, jsx_file):
        """Nested arrows are qualified so two same-named handlers cannot collide."""
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(jsx_file)
        handle = next(f for f in functions if f.name == "handleSave")
        assert handle.qualified_name == "Profile.handleSave"

    def test_anonymous_inline_callbacks_not_indexed(self, jsx_file):
        """onClick={() => ...} has no derivable name and must be skipped."""
        parser = TreeSitterParser()
        functions, _ = parser.parse_file(jsx_file)
        assert all(f.name for f in functions)
        assert not any("anonymous" in f.name for f in functions)
        # Profile, handleSave, renderRaw — no inline-callback noise
        assert len(functions) == 3

    def test_same_name_handlers_in_two_components_do_not_collide(self, tmp_path):
        src = TWO_COMPONENTS_SAMPLE
        f = tmp_path / "Forms.jsx"
        f.write_text(src)
        index = CodeIndex()
        index.build(str(f))
        matches = index.find_symbol("onSubmit")
        assert len(matches) == 2
        quals = {m["qualified_name"] for m in matches}
        assert quals == {"A.onSubmit", "B.onSubmit"}

    def test_jsx_indexed_via_build(self, index, jsx_file):
        stats = index.build(jsx_file)
        assert stats["files_parsed"] == 1
        assert stats["functions_found"] == 3
        assert stats["files_with_syntax_errors"] == 0

    def test_syntax_errors_are_reported(self, index, tmp_path):
        f = tmp_path / "broken.ts"
        f.write_text(BROKEN_TS_SAMPLE)
        stats = index.build(str(f))
        assert stats["files_with_syntax_errors"] == 1
        assert stats["errors"] == 0

    def test_mjs_and_mts_extensions_indexed(self, tmp_path):
        (tmp_path / "a.mjs").write_text(MJS_SAMPLE)
        (tmp_path / "b.mts").write_text(MTS_SAMPLE)
        index = CodeIndex()
        stats = index.build(str(tmp_path))
        assert stats["files_parsed"] == 2
        names = {f["name"] for f in index.get_all_functions()}
        assert {"fromMjs", "fromMts"} <= names


# --- Query interface (FR-022) ---

class TestQueryInterface:
    """Tests for the code index query interface."""

    def test_get_function_body(self, index, python_file):
        index.build(python_file)
        body = index.get_function_body(python_file, "sanitize")
        assert body is not None
        assert "return text.strip()" in body

    def test_get_function_body_not_found(self, index, python_file):
        index.build(python_file)
        body = index.get_function_body(python_file, "nonexistent")
        assert body is None

    def test_get_callers(self, index, python_file):
        index.build(python_file)
        callers = index.get_callers("sanitize")
        caller_names = [c["name"] for c in callers]
        assert "validate_input" in caller_names

    def test_get_callees(self, index, python_file):
        index.build(python_file)
        callees = index.get_callees(python_file, "validate_input")
        assert "sanitize" in callees

    def test_find_symbol(self, index, python_file):
        index.build(python_file)
        results = index.find_symbol("login")
        assert len(results) == 1
        assert results[0]["class_name"] == "AuthHandler"

    def test_find_symbol_not_found(self, index, python_file):
        index.build(python_file)
        results = index.find_symbol("nonexistent_function")
        assert results == []

    def test_list_functions_in_file(self, index, python_file):
        index.build(python_file)
        funcs = index.list_functions_in_file(python_file)
        names = [f["name"] for f in funcs]
        assert "read_config" in names
        assert "validate_input" in names

    def test_full_text_search(self, index, python_file):
        index.build(python_file)
        results = index.full_text_search("password")
        assert len(results) >= 2  # login and check_password both mention password

    def test_full_text_search_case_insensitive(self, index, python_file):
        index.build(python_file)
        results = index.full_text_search("ValueError")
        assert len(results) >= 1

    def test_get_stats(self, index, multi_lang_dir):
        index.build(multi_lang_dir)
        stats = index.get_stats()
        assert stats["total_functions"] >= 10
        assert stats["total_files"] == 3
        assert "python" in stats["languages"]
        assert "java" in stats["languages"]
        assert "javascript" in stats["languages"]


# --- Persistence ---

class TestPersistence:
    """Tests for index save/load."""

    def test_save_and_load(self, index, python_file, tmp_path):
        index.build(python_file)
        save_path = str(tmp_path / "index.json")
        index.save(save_path)
        assert os.path.exists(save_path)

        new_index = CodeIndex()
        assert new_index.load(save_path)
        assert new_index.is_queryable

        body = new_index.get_function_body(python_file, "sanitize")
        assert body is not None
        assert "return text.strip()" in body

    def test_save_atomic(self, index, python_file, tmp_path):
        index.build(python_file)
        save_path = str(tmp_path / "index.json")
        index.save(save_path)
        # .tmp file should not remain (atomic rename)
        assert not os.path.exists(save_path + ".tmp")

    def test_load_nonexistent(self, index):
        assert index.load("/nonexistent/path.json") is False

    def test_load_preserves_call_graph(self, index, python_file, tmp_path):
        index.build(python_file)
        save_path = str(tmp_path / "index.json")
        index.save(save_path)

        new_index = CodeIndex()
        new_index.load(save_path)
        callers = new_index.get_callers("sanitize")
        assert len(callers) >= 1


# --- FunctionInfo ---

class TestFunctionInfo:
    """Tests for FunctionInfo data class."""

    def test_qualified_name_with_class(self):
        f = FunctionInfo("login", "app.py", 1, 5, "body", "python", "Auth")
        assert f.qualified_name == "Auth.login"

    def test_qualified_name_without_class(self):
        f = FunctionInfo("main", "app.py", 1, 5, "body", "python")
        assert f.qualified_name == "main"

    def test_key(self):
        f = FunctionInfo("login", "app.py", 1, 5, "body", "python", "Auth")
        assert f.key == "app.py:Auth.login"

    def test_to_dict(self):
        f = FunctionInfo("main", "app.py", 1, 5, "def main(): pass", "python")
        d = f.to_dict()
        assert d["name"] == "main"
        assert d["file_path"] == "app.py"
        assert d["start_line"] == 1
        assert d["end_line"] == 5
        assert d["language"] == "python"
