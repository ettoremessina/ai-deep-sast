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

"""Test fixture for Zip Slip detection rules.
Contains INTENTIONALLY VULNERABLE code — do NOT fix."""

import os
import zipfile
import tarfile


# VULNERABLE: zipinfo.filename used in os.path.join without validation
def extract_zip_vulnerable(zip_path, dest_dir):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            file_path = os.path.join(dest_dir, info.filename)
            with zf.open(info) as src, open(file_path, 'wb') as dst:
                dst.write(src.read())


# VULNERABLE: tarinfo.name used in os.path.join without validation
def extract_tar_vulnerable(tar_path, dest_dir):
    with tarfile.open(tar_path, 'r:gz') as tf:
        for member in tf.getmembers():
            target_path = os.path.join(dest_dir, member.name)
            with open(target_path, 'wb') as f:
                f.write(tf.extractfile(member).read())


# SAFE: uses os.path.realpath to validate destination
def extract_zip_safe(zip_path, dest_dir):
    dest_dir = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            file_path = os.path.realpath(os.path.join(dest_dir, info.filename))
            if not file_path.startswith(dest_dir + os.sep):
                raise ValueError(f"Zip Slip detected: {info.filename}")
            with zf.open(info) as src, open(file_path, 'wb') as dst:
                dst.write(src.read())
