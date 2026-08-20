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


CSHARP_TOP_LEVEL_SAMPLE = '''using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(policy =>
{
    policy.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader());
});

builder.Services.AddAuthentication("Bearer").AddJwtBearer();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.MapControllers();
app.Run();
'''

CSHARP_EXPLICIT_MAIN_SAMPLE = '''using System;

namespace App
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Configure();
        }

        private static void Configure()
        {
            Console.WriteLine("configured");
        }
    }
}
'''

CSHARP_CLASS_ONLY_SAMPLE = '''namespace App.Models
{
    public class User
    {
        public string Name { get; set; }
    }
}
'''


PYTHON_TRIVIAL_BODY_SAMPLE = '''
def placeholder():
    pass

def ellipsis_body():
    ...
'''

JS_EXPRESSION_ARROW_SAMPLE = '''
const double = (x) => x * 2;
'''

CSHARP_BODYLESS_SAMPLE = '''namespace App.Services
{
    public interface IMasterDataService
    {
        Task<int> CountAsync();
        Task DeleteAsync(int id);
    }

    public abstract class ServiceBase
    {
        protected abstract Task ExecuteAsync();

        protected void Log(string message)
        {
            Console.WriteLine(message);
        }
    }

    public partial class MasterDataService : ServiceBase
    {
        partial void OnConfiguring();

        public MasterDataService()
        {
            Setup();
        }

        public int Count => _items.Count;

        protected override async Task ExecuteAsync()
        {
            await DoWorkAsync();
        }
    }
}
'''

JAVA_BODYLESS_SAMPLE = '''package com.example;

public interface Repository {
    User findById(String id);
    void save(User user);
}

abstract class RepositoryBase implements Repository {
    public abstract void flush();

    public void clear() {
        cache.clear();
    }
}
'''


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
    # min_function_lines=1: these tests exercise indexing/query/persistence
    # behaviour with small fixture bodies, not the trivial-skip feature
    # itself, which has its own dedicated tests below.
    return CodeIndex(min_function_lines=1)


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

    def test_reindex_on_change_does_not_duplicate_name_entries(self, index, tmp_path):
        """Re-indexing a modified file must not leave stale _by_name entries.

        When a function's body changes but its start_line does not, its key
        is identical across builds. _remove_file must still recognise and
        strip the old _by_name entry before the rebuild re-adds it, or
        find_symbol returns the same function twice.
        """
        f = tmp_path / "app.py"
        f.write_text("def foo():\n    pass\n")
        index.build(str(tmp_path))
        assert len(index.find_symbol("foo")) == 1

        f.write_text("def foo():\n    return 1\n")
        index.build(str(tmp_path))

        results = index.find_symbol("foo")
        assert len(results) == 1
        assert index._by_name["foo"] == list(dict.fromkeys(index._by_name["foo"]))

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
        index = CodeIndex(min_function_lines=1)  # 1-line handlers by design
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
        index = CodeIndex(min_function_lines=1)  # 1-line samples by design
        stats = index.build(str(tmp_path))
        assert stats["files_parsed"] == 2
        names = {f["name"] for f in index.get_all_functions()}
        assert {"fromMjs", "fromMts"} <= names


# --- C# top-level statements ---

class TestCSharpTopLevel:
    """
    C# top-level statements (.NET 6+) belong to no method declaration, yet that
    is where modern ASP.NET wires up authentication, CORS and endpoints.
    """

    def _parse(self, tmp_path, name, source):
        f = tmp_path / name
        f.write_text(source)
        return TreeSitterParser().parse_file(str(f))

    def test_top_level_statements_indexed(self, tmp_path):
        functions, _ = self._parse(tmp_path, "Program.cs", CSHARP_TOP_LEVEL_SAMPLE)
        names = [f.name for f in functions]
        assert names.count("<top-level>") == 1

    def test_top_level_body_covers_the_configuration(self, tmp_path):
        functions, _ = self._parse(tmp_path, "Program.cs", CSHARP_TOP_LEVEL_SAMPLE)
        top = next(f for f in functions if f.name == "<top-level>")
        assert "AllowAnyOrigin" in top.body
        assert "AddJwtBearer" in top.body
        assert "app.Run()" in top.body
        # The using directives above the first statement are not part of it.
        assert "using Microsoft" not in top.body

    def test_top_level_spans_first_to_last_statement(self, tmp_path):
        functions, _ = self._parse(tmp_path, "Program.cs", CSHARP_TOP_LEVEL_SAMPLE)
        top = next(f for f in functions if f.name == "<top-level>")
        lines = CSHARP_TOP_LEVEL_SAMPLE.splitlines()
        assert lines[top.start_line - 1].startswith("var builder")
        assert lines[top.end_line - 1].startswith("app.Run()")

    def test_calls_attributed_to_top_level(self, tmp_path):
        functions, calls = self._parse(tmp_path, "Program.cs", CSHARP_TOP_LEVEL_SAMPLE)
        top = next(f for f in functions if f.name == "<top-level>")
        callees = {callee for caller, callee in calls if caller == top.key}
        # C# callee names keep their receiver chain (pre-existing behaviour of
        # _extract_callee_name for member_access_expression), unlike Java/Python.
        assert "builder.Services.AddCors" in callees
        assert "app.UseAuthentication" in callees

    def test_explicit_main_produces_no_top_level(self, tmp_path):
        functions, _ = self._parse(tmp_path, "Program.cs", CSHARP_EXPLICIT_MAIN_SAMPLE)
        names = {f.name for f in functions}
        assert "Main" in names
        assert "Configure" in names
        assert "<top-level>" not in names

    def test_class_only_file_produces_no_top_level(self, tmp_path):
        functions, _ = self._parse(tmp_path, "User.cs", CSHARP_CLASS_ONLY_SAMPLE)
        assert "<top-level>" not in {f.name for f in functions}

    def test_python_module_level_code_unaffected(self, tmp_path):
        functions, _ = self._parse(tmp_path, "app.py", PYTHON_SAMPLE)
        assert "<top-level>" not in {f.name for f in functions}

    def test_top_level_reaches_the_index(self, tmp_path):
        f = tmp_path / "Program.cs"
        f.write_text(CSHARP_TOP_LEVEL_SAMPLE)
        index = CodeIndex()
        stats = index.build(str(f))
        assert stats["functions_found"] == 1
        assert stats["files_with_syntax_errors"] == 0
        assert [m["name"] for m in index.find_symbol("<top-level>")] == ["<top-level>"]


# --- Declarations with no body ---

class TestBodylessDeclarations:
    """
    Interface, abstract and partial declarations are signatures with no
    implementation: sending them to the LLM costs a call and can find nothing.
    """

    def _names(self, tmp_path, name, source):
        f = tmp_path / name
        f.write_text(source)
        functions, _ = TreeSitterParser().parse_file(str(f))
        return {fn.qualified_name for fn in functions}

    def test_csharp_interface_methods_skipped(self, tmp_path):
        names = self._names(tmp_path, "IMasterDataService.cs", CSHARP_BODYLESS_SAMPLE)
        assert "IMasterDataService.CountAsync" not in names
        assert "IMasterDataService.DeleteAsync" not in names

    def test_csharp_abstract_method_skipped(self, tmp_path):
        names = self._names(tmp_path, "ServiceBase.cs", CSHARP_BODYLESS_SAMPLE)
        assert "ServiceBase.ExecuteAsync" not in names

    def test_csharp_partial_declaration_skipped(self, tmp_path):
        names = self._names(tmp_path, "MasterDataService.cs", CSHARP_BODYLESS_SAMPLE)
        assert "MasterDataService.OnConfiguring" not in names

    def test_csharp_implementations_still_indexed(self, tmp_path):
        names = self._names(tmp_path, "MasterDataService.cs", CSHARP_BODYLESS_SAMPLE)
        assert "ServiceBase.Log" in names
        assert "MasterDataService.MasterDataService" in names
        assert "MasterDataService.ExecuteAsync" in names

    def test_java_interface_methods_skipped(self, tmp_path):
        names = self._names(tmp_path, "Repository.java", JAVA_BODYLESS_SAMPLE)
        assert "Repository.findById" not in names
        assert "Repository.save" not in names
        assert "RepositoryBase.flush" not in names
        assert "RepositoryBase.clear" in names

    def test_python_trivial_bodies_still_indexed(self, tmp_path):
        f = tmp_path / "stub.py"
        f.write_text(PYTHON_TRIVIAL_BODY_SAMPLE)
        functions, _ = TreeSitterParser().parse_file(str(f))
        assert {fn.name for fn in functions} == {"placeholder", "ellipsis_body"}

    def test_js_expression_arrow_still_indexed(self, tmp_path):
        f = tmp_path / "util.js"
        f.write_text(JS_EXPRESSION_ARROW_SAMPLE)
        functions, _ = TreeSitterParser().parse_file(str(f))
        assert {fn.name for fn in functions} == {"double"}

    def test_bodyless_declarations_not_counted_as_functions(self, tmp_path):
        f = tmp_path / "IMasterDataService.cs"
        f.write_text(CSHARP_BODYLESS_SAMPLE)
        index = CodeIndex()
        stats = index.build(str(f))
        # Only Log, the constructor and the ExecuteAsync override remain
        # (C# properties are not indexed at all).
        assert stats["functions_found"] == 3
        assert stats["files_with_syntax_errors"] == 0


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
        assert f.key == "app.py:Auth.login:1"

    def test_to_dict(self):
        f = FunctionInfo("main", "app.py", 1, 5, "def main(): pass", "python")
        d = f.to_dict()
        assert d["name"] == "main"
        assert d["file_path"] == "app.py"
        assert d["start_line"] == 1
        assert d["end_line"] == 5
        assert d["language"] == "python"


def test_same_named_functions_in_one_file_all_indexed(tmp_path):
    """Two callbacks with the same name must not overwrite each other."""
    f = tmp_path / "grid.tsx"
    f.write_text(
        "export const getColumns = () => [\n"
        "  { renderCell: (p) => <span>{p.a}</span> },\n"
        "  { renderCell: (p) => <span>{p.b}</span> },\n"
        "];\n"
    )
    # min_function_lines=1: this test is about key uniqueness, not triviality.
    idx = CodeIndex(min_function_lines=1)
    stats = idx.build(str(f))
    names = [fn["name"] for fn in idx.get_all_functions()]
    assert names.count("renderCell") == 2
    assert stats["functions_found"] == len(idx.get_all_functions())


def test_key_includes_start_line():
    a = FunctionInfo("f", "a.ts", 1, 2, "body", "typescript")
    b = FunctionInfo("f", "a.ts", 10, 11, "body", "typescript")
    assert a.key != b.key


def test_trivial_functions_skipped_by_default(tmp_path):
    f = tmp_path / "cb.ts"
    f.write_text(
        "export const pick = (x) => x.id;\n"
        "export function real(items) {\n"
        "    const out = [];\n"
        "    for (const i of items) {\n"
        "        out.push(i.id);\n"
        "    }\n"
        "    return out;\n"
        "}\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    names = [fn["name"] for fn in idx.get_all_functions()]
    assert names == ["real"]
    assert stats["functions_skipped_trivial"] == 1


def test_threshold_can_be_lowered(tmp_path):
    f = tmp_path / "cb.ts"
    f.write_text("export const pick = (x) => x.id;\n")
    idx = CodeIndex(min_function_lines=1)
    idx.build(str(f))
    assert [fn["name"] for fn in idx.get_all_functions()] == ["pick"]


CONFIG_FILE = """\
const configVariables = {
    backendBaseUrl: import.meta.env.VITE_BACKEND_URL as string,
};
export default configVariables;
"""

# Contains "Auth", which matches the auth signal. Only the re-export check keeps
# it out — which is exactly what this fixture is here to exercise. The grouped
# export is spread across lines the way Prettier formats it by default; a
# line-by-line barrel check never recognises its interior lines (e.g.
# "    AuthenticatedLayout,") as anything and wrongly admits the file.
BARREL_FILE = """\
export * from './PageLayout';
export {
    AuthenticatedLayout,
    DefaultLayout,
} from './LayoutComponents';
"""


def test_config_file_without_functions_becomes_a_unit(tmp_path):
    (tmp_path / "configVariables.ts").write_text(CONFIG_FILE)
    idx = CodeIndex()
    stats = idx.build(str(tmp_path))
    units = idx.get_all_functions()
    assert len(units) == 1
    assert units[0]["name"] == "(file)"
    assert "VITE_BACKEND_URL" in units[0]["body"]
    assert stats["whole_file_units"] == 1


def test_barrel_file_is_not_a_unit(tmp_path):
    (tmp_path / "index.ts").write_text(BARREL_FILE)
    idx = CodeIndex()
    stats = idx.build(str(tmp_path))
    assert idx.get_all_functions() == []
    assert stats["whole_file_units"] == 0


def test_oversized_config_file_is_skipped_not_truncated(tmp_path):
    big = tmp_path / "huge.ts"
    big.write_text("const c = { url: 'https://x' };\n" + ("// filler\n" * 20000))
    idx = CodeIndex()
    stats = idx.build(str(big))
    assert idx.get_all_functions() == []
    assert stats["whole_file_units"] == 0


def test_import_meta_env_reads_are_collected(tmp_path):
    (tmp_path / "config.ts").write_text(
        "const c = {\n"
        "    a: import.meta.env.VITE_API_URL as string,\n"
        "    b: import.meta.env.VITE_CLIENT_ID as string,\n"
        "};\n"
        "export default c;\n"
    )
    idx = CodeIndex()
    idx.build(str(tmp_path))
    reads = idx.get_env_reads()
    assert sorted(reads) == ["VITE_API_URL", "VITE_CLIENT_ID"]
    assert reads["VITE_API_URL"] == [str(tmp_path / "config.ts")]


def test_html_entity_in_jsx_is_not_a_partial_parse(tmp_path):
    f = tmp_path / "label.tsx"
    f.write_text(
        "export function AreaLabel() {\n"
        "    return <>Area (mm&sup2;)</>;\n"
        "}\n"
    )
    # min_function_lines=1: this is a 1-line body by design, testing entity
    # handling in isolation from the unrelated trivial-function-skip feature.
    idx = CodeIndex(min_function_lines=1)
    stats = idx.build(str(f))
    assert [fn["name"] for fn in idx.get_all_functions()] == ["AreaLabel"]
    assert stats["files_with_syntax_errors"] == 0


def test_genuinely_broken_file_still_reports(tmp_path):
    f = tmp_path / "broken.tsx"
    f.write_text("export function A() { return <div>; }\nfunction (((\n")
    idx = CodeIndex()
    stats = idx.build(str(f))
    assert stats["files_with_syntax_errors"] == 1


def test_entity_plus_unrelated_broken_function_still_reports(tmp_path):
    # A valid entity in one function must not exonerate a real syntax error
    # in an unrelated function later in the same file. _first_error_node
    # returns only the first error in DFS order, and the entity sits before
    # the real break here, so a check that only inspects that first node
    # would wrongly clear the whole file.
    f = tmp_path / "mixed.tsx"
    f.write_text(
        "export function AreaLabel() {\n"
        "    return <>Area (mm&sup2;)</>;\n"
        "}\n"
        "\n"
        "export function A() { return <div>; }\n"
        "function (((\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    assert stats["files_with_syntax_errors"] == 1


def test_unbalanced_construct_before_entity_still_reports(tmp_path):
    # tree-sitter can merge an unrecoverable region into one ERROR node that
    # spans from a stray paren through a later, otherwise-valid entity. The
    # node's text then *contains* an entity even though the entity is not
    # the defect - a check that greps the node's text for an entity shape
    # would wrongly clear the file.
    f = tmp_path / "unbalanced.tsx"
    f.write_text(
        "function (((\n"
        "export function AreaLabel() {\n"
        "    return <>Area (mm&sup2;)</>;\n"
        "}\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    assert stats["files_with_syntax_errors"] == 1
