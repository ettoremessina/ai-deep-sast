/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Test fixture for Zip Slip detection rules.
// Contains INTENTIONALLY VULNERABLE code — do NOT fix.

import java.io.*;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.nio.file.Paths;

public class TestZipSlip {

    // VULNERABLE: entry.getName() flows directly into new File()
    public static void extractVulnerable(ZipFile zip, File destDir) throws IOException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String currentEntry = entry.getName();
            File destFile = new File(destDir, currentEntry);
            File parent = destFile.getParentFile();
            parent.mkdirs();
            if (!entry.isDirectory()) {
                InputStream is = zip.getInputStream(entry);
                FileOutputStream fos = new FileOutputStream(destFile);
                byte[] buf = new byte[1024];
                int len;
                while ((len = is.read(buf)) > 0) {
                    fos.write(buf, 0, len);
                }
                fos.close();
                is.close();
            }
        }
    }

    // VULNERABLE: using Paths.get() as sink
    public static void extractVulnerablePaths(ZipFile zip, String destDir) throws IOException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            java.nio.file.Path destPath = Paths.get(destDir, entry.getName());
            // write file...
        }
    }

    // SAFE: uses getCanonicalPath() to validate
    public static void extractSafe(ZipFile zip, File destDir) throws IOException {
        String destDirPath = destDir.getCanonicalPath();
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            File destFile = new File(destDir, entry.getName());
            String destFilePath = destFile.getCanonicalPath();
            if (!destFilePath.startsWith(destDirPath + File.separator)) {
                throw new IOException("Zip Slip detected: " + entry.getName());
            }
            // safe to extract...
        }
    }
}
