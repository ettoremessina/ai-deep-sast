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
"""
Test fixture: Python source code secrets detection.
Lines marked DETECT should be flagged.
Lines marked SKIP should NOT be flagged.
"""

# --- DETECT: hardcoded credentials in source ---
DB_PASSWORD = "p0stgr3s_adm1n_2024"
API_KEY = "sk_live_abc123def456"
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.test.signature"
APP_SECRET = "xK9mP2vL8nQ4wR7j"

# --- SKIP: value too short (< 4 chars) ---
PWD = "abc"

# --- SKIP: value is a keyword/path, not a real secret ---
PASSWORD_FILE = "password.txt"
SECRET_CONFIG = "secret.yaml"

# --- SKIP: not a string literal assignment ---
import os
password = os.getenv("DB_PASSWORD")
