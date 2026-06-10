// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package com.test.fixtures;

/**
 * Test fixture: Java source code secrets detection.
 * Lines marked DETECT should be flagged.
 * Lines marked SKIP should NOT be flagged.
 */
public class TestSecrets {

    public void testMethod() {
        // --- DETECT: hardcoded credentials in source ---
        String DB_PASSWORD = "p0stgr3s_adm1n_2024";
        String API_KEY = "sk_live_abc123def456";
        String AUTH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.test.signature";
        String APP_SECRET = "xK9mP2vL8nQ4wR7j";

        // --- SKIP: value too short (< 4 chars) ---
        String PWD = "abc";

        // --- SKIP: value is a keyword/path, not a real secret ---
        String PASSWORD_FILE = "password.txt";
        String SECRET_CONFIG = "secret.yaml";

        // --- SKIP: not a string literal assignment ---
        String password = System.getenv("DB_PASSWORD");
    }
}
