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

/**
 * Sample Vulnerable Java File
 * ===============================
 * This file contains intentional security vulnerabilities
 * for testing the AI Deep SAST.
 *
 * WARNING: Do NOT use any of this code in production.
 *
 * Covers:
 *   - A03:2021 - Injection (SQL Injection)
 *   - A07:2021 - Identification and Authentication Failures (hardcoded credentials)
 *   - A08:2021 - Software and Data Integrity Failures (XXE)
 *   - A01:2021 - Broken Access Control (path traversal)
 *   - A02:2021 - Cryptographic Failures (weak SSL, unencrypted socket)
 */

import java.io.*;
import java.net.*;
import java.sql.*;
import javax.net.ssl.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import javax.servlet.http.*;

public class SampleVuln {

    // ============================================================
    // A07:2021 - Hardcoded credentials in source code
    // ============================================================
    // VULNERABLE: Hardcoded database password in Java source
    private static final String DB_PASSWORD = "Pr0dP@ssw0rd!";
    private static final String DB_USER = "admin";
    private static final String API_SECRET = "sk_live_51Hf8x2z9Y0qR4wT6uV8";
    private static final String REDIS_AUTH = "R3d1sC@ch3P@ss!";

    // ============================================================
    // A03:2021 - Injection (SQL Injection)
    // ============================================================
    public ResultSet getUserById(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:sqlserver://10.200.50.100:1433;databaseName=AppDB",
            DB_USER, DB_PASSWORD
        );
        Statement stmt = conn.createStatement();
        // VULNERABLE: Direct string concatenation in SQL query
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    // ============================================================
    // A03:2021 - Injection (formatted SQL string)
    // ============================================================
    public void updateUserStatus(String userId, String status) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:sqlserver://localhost:1433;databaseName=AppDB",
            DB_USER, DB_PASSWORD
        );
        Statement stmt = conn.createStatement();
        // VULNERABLE: String.format in SQL
        String query = String.format(
            "UPDATE users SET status = '%s' WHERE id = '%s'", status, userId
        );
        stmt.executeUpdate(query);
    }

    // ============================================================
    // A08:2021 - XXE (DocumentBuilderFactory without disabling DTD)
    // ============================================================
    public void parseXmlInput(InputStream xmlInput) throws Exception {
        // VULNERABLE: XXE - DTD processing not disabled
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xmlInput);
    }

    // ============================================================
    // A01:2021 - Broken Access Control (path traversal)
    // ============================================================
    public void serveFile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // VULNERABLE: Path traversal - user input used directly in file path
        String filename = request.getParameter("file");
        File file = new File("/var/data/" + filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = fis.readAllBytes();
        response.getOutputStream().write(data);
        fis.close();
    }

    // ============================================================
    // A02:2021 - Cryptographic Failures (weak SSL context)
    // ============================================================
    public HttpsURLConnection createWeakConnection(String url) throws Exception {
        // VULNERABLE: Using TLS 1.0 which is deprecated and insecure
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, null);
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        return conn;
    }

    // ============================================================
    // A02:2021 - Cryptographic Failures (unencrypted socket)
    // ============================================================
    public Socket createUnencryptedSocket(String host, int port) throws IOException {
        // VULNERABLE: Plain TCP socket with no encryption
        return new Socket(host, port);
    }
}
