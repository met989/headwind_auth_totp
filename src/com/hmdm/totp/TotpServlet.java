package com.hmdm.totp;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * REST API Servlet for Headwind MDM 2FA / TOTP authentication and management plugin.
 *
 * Endpoints:
 *   GET  /api/status        -> Returns current user login & 2FA status
 *   GET  /api/setup         -> Generates secret, QR Code SVG, and backup codes for setup
 *   POST /api/verify        -> Verifies 6-digit code (or backup code) and unlocks session
 *   GET  /api/admin/users   -> Lists all MDM users with their 2FA status (Admin only)
 *   POST /api/admin/toggle  -> Enables or disables 2FA for a user (Admin only)
 *   POST /api/admin/reset   -> Resets 2FA secret for an individual user (Admin only)
 *   POST /api/logout        -> Invalidates 2FA verification for this session
 */
public class TotpServlet extends HttpServlet {

    // Tracks verified MDM sessions: jsessionId -> expiryTimestamp
    private static final ConcurrentHashMap<String, Long> VERIFIED_SESSIONS = new ConcurrentHashMap<>();

    // Tracks pending first-time setups: jsessionId -> PendingSetup
    private static final ConcurrentHashMap<String, PendingSetup> PENDING_SETUPS = new ConcurrentHashMap<>();

    private static class PendingSetup {
        String username;
        String secret;
        List<String> backupCodes;
        long timestamp;

        PendingSetup(String username, String secret, List<String> backupCodes) {
            this.username = username;
            this.secret = secret;
            this.backupCodes = backupCodes;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static class HmdmUser {
        public int id;
        public String login;
        public String name;
        public String email;
        public String roleName;
        public boolean isSuperadmin;
        public boolean isAdmin;
    }

    public static class AdminUserRecord {
        public int id;
        public String login;
        public String name;
        public String email;
        public String role;
        public boolean superadmin;
        public boolean enabled;
        public boolean configured;
        public long createdAt;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = getSubPath(req);
        resp.setContentType("application/json;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

        String cookieHeader = req.getHeader("Cookie");
        String jsessionId = extractJSessionId(cookieHeader);
        HmdmUser user = getHmdmUser(cookieHeader);

        if (user == null || jsessionId == null) {
            resp.getWriter().write("{\"status\":\"OK\",\"data\":{\"authenticated\":false}}");
            return;
        }

        if ("/status".equals(path)) {
            handleStatus(resp, jsessionId, user);
        } else if ("/setup".equals(path)) {
            handleSetup(resp, jsessionId, user);
        } else if ("/admin/users".equals(path)) {
            handleAdminUsers(resp, user, cookieHeader);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Not found\"}");
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = getSubPath(req);
        resp.setContentType("application/json;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

        String cookieHeader = req.getHeader("Cookie");
        String jsessionId = extractJSessionId(cookieHeader);
        HmdmUser user = getHmdmUser(cookieHeader);

        if (user == null || jsessionId == null) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Please log in to Headwind MDM first.\"}");
            return;
        }

        String body = readBody(req);

        if ("/verify".equals(path)) {
            handleVerify(resp, jsessionId, user, body);
        } else if ("/admin/toggle".equals(path)) {
            handleAdminToggle(resp, user, body);
        } else if ("/admin/reset".equals(path) || "/reset".equals(path)) {
            handleAdminReset(resp, user, body);
        } else if ("/logout".equals(path)) {
            VERIFIED_SESSIONS.remove(jsessionId);
            PENDING_SETUPS.remove(jsessionId);
            resp.getWriter().write("{\"status\":\"OK\",\"message\":\"Logged out\"}");
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Not found\"}");
        }
    }

    private void handleStatus(HttpServletResponse resp, String jsessionId, HmdmUser user) throws IOException {
        boolean enabled = StorageService.isUserEnabled(user.login);
        boolean configured = StorageService.isUserConfigured(user.login);
        // If 2FA is NOT enabled for this user, session is considered verified immediately!
        boolean verified = !enabled || isSessionVerified(jsessionId);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"status\":\"OK\",\"data\":{");
        sb.append("\"authenticated\":true,");
        sb.append("\"username\":\"").append(escapeJson(user.login)).append("\",");
        sb.append("\"name\":\"").append(escapeJson(user.name)).append("\",");
        sb.append("\"role\":\"").append(escapeJson(user.roleName)).append("\",");
        sb.append("\"enabled\":").append(enabled).append(",");
        sb.append("\"configured\":").append(configured).append(",");
        sb.append("\"verified\":").append(verified).append(",");
        sb.append("\"isAdmin\":").append(user.isAdmin).append(",");
        sb.append("\"isSuperadmin\":").append(user.isSuperadmin);
        sb.append("}}");

        resp.getWriter().write(sb.toString());
    }

    private void handleSetup(HttpServletResponse resp, String jsessionId, HmdmUser user) throws IOException {
        PendingSetup pending = PENDING_SETUPS.get(jsessionId);
        String secret;
        List<String> backupCodes;

        if (pending != null && user.login.equals(pending.username)) {
            // Keep the exact same secret and backup codes for this session so it never changes under the user
            secret = pending.secret;
            backupCodes = pending.backupCodes;
        } else {
            secret = TotpService.generateSecretKey(16);
            backupCodes = TotpService.generateBackupCodes(5);
            PENDING_SETUPS.put(jsessionId, new PendingSetup(user.login, secret, backupCodes));
        }

        String otpauthUri = TotpService.getOtpAuthUri("Headwind MDM", user.login, secret);
        String qrDataUri = QrCodeGenerator.generateSvgDataUri(otpauthUri, 3);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"status\":\"OK\",\"data\":{");
        sb.append("\"username\":\"").append(escapeJson(user.login)).append("\",");
        sb.append("\"secret\":\"").append(escapeJson(secret)).append("\",");
        sb.append("\"otpauthUri\":\"").append(escapeJson(otpauthUri)).append("\",");
        sb.append("\"qrCode\":\"").append(escapeJson(qrDataUri)).append("\",");
        sb.append("\"backupCodes\":[");
        for (int i = 0; i < backupCodes.size(); i++) {
            sb.append("\"").append(escapeJson(backupCodes.get(i))).append("\"");
            if (i < backupCodes.size() - 1) sb.append(",");
        }
        sb.append("]");
        sb.append("}}");

        resp.getWriter().write(sb.toString());
    }

    private void handleVerify(HttpServletResponse resp, String jsessionId, HmdmUser user, String body) throws IOException {
        String code = extractJsonField(body, "code");
        String backupCode = extractJsonField(body, "backupCode");

        // Check if there is a pending setup for this session (first access!)
        PendingSetup pending = PENDING_SETUPS.get(jsessionId);
        if (pending != null && pending.username.equalsIgnoreCase(user.login)) {
            boolean valid = TotpService.verifyCode(pending.secret, code);
            if (valid) {
                // Permanently save user secret & backup codes
                StorageService.saveUser(user.login, pending.secret, pending.backupCodes);
                PENDING_SETUPS.remove(jsessionId);
                markSessionVerified(jsessionId);

                resp.getWriter().write("{\"status\":\"OK\",\"message\":\"2FA successfully enabled and verified.\"}");
                return;
            } else {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Invalid code. Please check your smartphone time settings and try again.\"}");
                return;
            }
        }

        // Existing user verification
        String secret = StorageService.getSecret(user.login);
        if (secret == null) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"2FA is not yet configured for this user.\"}");
            return;
        }

        boolean verified = false;
        if (code != null && !code.trim().isEmpty()) {
            verified = TotpService.verifyCode(secret, code);
        }

        if (!verified && backupCode != null && !backupCode.trim().isEmpty()) {
            verified = StorageService.consumeBackupCode(user.login, backupCode);
        }

        if (verified) {
            markSessionVerified(jsessionId);
            resp.getWriter().write("{\"status\":\"OK\",\"message\":\"2FA verification successful.\"}");
        } else {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Invalid security code. Please try again.\"}");
        }
    }

    private void handleAdminUsers(HttpServletResponse resp, HmdmUser currentUser, String cookieHeader) throws IOException {
        if (!currentUser.isAdmin) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Access denied: administrator privileges required.\"}");
            return;
        }

        List<AdminUserRecord> users = getMdmUsers(cookieHeader);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"status\":\"OK\",\"data\":[");
        for (int i = 0; i < users.size(); i++) {
            AdminUserRecord u = users.get(i);
            sb.append("{");
            sb.append("\"id\":").append(u.id).append(",");
            sb.append("\"username\":\"").append(escapeJson(u.login)).append("\",");
            sb.append("\"name\":\"").append(escapeJson(u.name)).append("\",");
            sb.append("\"email\":\"").append(escapeJson(u.email)).append("\",");
            sb.append("\"role\":\"").append(escapeJson(u.role)).append("\",");
            sb.append("\"superadmin\":").append(u.superadmin).append(",");
            sb.append("\"enabled\":").append(u.enabled).append(",");
            sb.append("\"configured\":").append(u.configured).append(",");
            sb.append("\"createdAt\":").append(u.createdAt);
            sb.append("}");
            if (i < users.size() - 1) sb.append(",");
        }
        sb.append("]}");

        resp.getWriter().write(sb.toString());
    }

    private void handleAdminToggle(HttpServletResponse resp, HmdmUser currentUser, String body) throws IOException {
        if (!currentUser.isAdmin) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Access denied: administrator privileges required.\"}");
            return;
        }

        String targetUser = extractJsonField(body, "username");
        if (targetUser == null || targetUser.trim().isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Missing username parameter.\"}");
            return;
        }

        boolean enabled = false;
        Matcher m = Pattern.compile("\"enabled\"\\s*:\\s*(true|false)").matcher(body);
        if (m.find()) {
            enabled = Boolean.parseBoolean(m.group(1));
        }

        StorageService.setUserEnabled(targetUser, enabled);
        String msg = "Two-factor authentication " + (enabled ? "enabled" : "disabled") + " for " + targetUser + ".";
        resp.getWriter().write("{\"status\":\"OK\",\"message\":\"" + escapeJson(msg) + "\"}");
    }

    private void handleAdminReset(HttpServletResponse resp, HmdmUser currentUser, String body) throws IOException {
        if (!currentUser.isAdmin) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("{\"status\":\"ERROR\",\"message\":\"Access denied: administrator privileges required.\"}");
            return;
        }

        String targetUser = extractJsonField(body, "username");
        if (targetUser == null || targetUser.trim().isEmpty()) {
            targetUser = extractJsonField(body, "targetUser");
        }
        if (targetUser == null || targetUser.trim().isEmpty()) {
            targetUser = currentUser.login;
        }

        boolean success = StorageService.resetUser(targetUser);
        String msg = "2FA reset successfully for " + targetUser + ". On next login, they will need to link a new QR code.";
        resp.getWriter().write("{\"status\":\"OK\",\"message\":\"" + escapeJson(msg) + "\"}");
    }

    private List<AdminUserRecord> getMdmUsers(String cookieHeader) {
        List<AdminUserRecord> list = new ArrayList<>();

        // 1. Try internal REST API call to Headwind MDM
        try {
            URL url = new URL("http://127.0.0.1:8080/rest/private/users/all");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            if (cookieHeader != null) conn.setRequestProperty("Cookie", cookieHeader);
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() == 200) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                }
                list = parseUsersFromJson(sb.toString());
            }
            conn.disconnect();
        } catch (Exception e) {
            System.err.println("[Headwind-TOTP] REST users/all query failed: " + e.getMessage());
        }

        // 2. Fallback to direct JDBC if REST API returned empty
        if (list.isEmpty()) {
            list = queryUsersFromDatabase();
        }

        // 3. Decorate each user with 2FA state
        for (AdminUserRecord u : list) {
            u.enabled = StorageService.isUserEnabled(u.login);
            u.configured = StorageService.isUserConfigured(u.login);
            StorageService.UserRecord rec = StorageService.getUserRecord(u.login);
            u.createdAt = (rec != null) ? rec.createdAt : 0L;
        }

        return list;
    }

    private Connection getDatabaseConnection() {
        String url = System.getProperty("JDBC.url", System.getenv("JDBC_URL"));
        String user = System.getProperty("JDBC.username", System.getenv("JDBC_USER"));
        String pass = System.getProperty("JDBC.password", System.getenv("JDBC_PASSWORD"));
        if (pass == null) pass = System.getenv("SQL_PASS");

        // Dynamically parse Headwind MDM's ROOT.xml if available in Tomcat
        if (url == null || user == null || pass == null) {
            String catalinaBase = System.getProperty("catalina.base", "/var/lib/tomcat10");
            File[] candidates = new File[] {
                new File(catalinaBase, "conf/Catalina/localhost/ROOT.xml"),
                new File("/var/lib/tomcat10/conf/Catalina/localhost/ROOT.xml"),
                new File("/var/lib/tomcat9/conf/Catalina/localhost/ROOT.xml"),
                new File("/var/lib/tomcat/conf/Catalina/localhost/ROOT.xml"),
                new File("/opt/tomcat/conf/Catalina/localhost/ROOT.xml"),
                new File("/etc/hmdm/ROOT.xml")
            };
            for (File cf : candidates) {
                if (cf.exists() && cf.canRead()) {
                    try {
                        String xml = new String(java.nio.file.Files.readAllBytes(cf.toPath()), StandardCharsets.UTF_8);
                        if (url == null) url = extractXmlParameter(xml, "JDBC.url");
                        if (user == null) user = extractXmlParameter(xml, "JDBC.username");
                        if (pass == null) pass = extractXmlParameter(xml, "JDBC.password");
                        if (url != null && user != null && pass != null) break;
                    } catch (Exception ignored) {}
                }
            }
        }

        if (url == null) url = "jdbc:postgresql://localhost:5432/hmdm";
        if (user == null) user = "hmdm";
        if (pass == null) pass = "";

        try {
            Class.forName("org.postgresql.Driver");
            return DriverManager.getConnection(url, user, pass);
        } catch (Throwable t) {
            System.err.println("[Headwind-TOTP] JDBC connection attempt failed: " + t.getMessage());
            return null;
        }
    }

    private static String extractXmlParameter(String xml, String paramName) {
        Pattern p1 = Pattern.compile("<Parameter\\s+[^>]*name=[\"']" + Pattern.quote(paramName) + "[\"'][^>]*value=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m1 = p1.matcher(xml);
        if (m1.find()) return m1.group(1);

        Pattern p2 = Pattern.compile("<Parameter\\s+[^>]*value=[\"']([^\"']*)[\"'][^>]*name=[\"']" + Pattern.quote(paramName) + "[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m2 = p2.matcher(xml);
        if (m2.find()) return m2.group(1);

        return null;
    }

    private List<AdminUserRecord> queryUsersFromDatabase() {
        List<AdminUserRecord> list = new ArrayList<>();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = getDatabaseConnection();
            if (conn == null) {
                return list;
            }
            stmt = conn.createStatement();
            String sql = "SELECT u.id, u.login, u.name, u.email, COALESCE(ur.name, 'User') as role_name, COALESCE(ur.superadmin, false) as is_superadmin " +
                    "FROM users u LEFT JOIN userroles ur ON u.userroleid = ur.id ORDER BY u.id ASC";
            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                AdminUserRecord u = new AdminUserRecord();
                u.id = rs.getInt("id");
                u.login = rs.getString("login");
                u.name = rs.getString("name");
                u.email = rs.getString("email");
                u.role = rs.getString("role_name");
                u.superadmin = rs.getBoolean("is_superadmin");
                list.add(u);
            }
        } catch (Throwable t) {
            System.err.println("[Headwind-TOTP] Database query failed: " + t.getMessage());
        } finally {
            try { if (rs != null) rs.close(); } catch (Exception ignored) {}
            try { if (stmt != null) stmt.close(); } catch (Exception ignored) {}
            try { if (conn != null) conn.close(); } catch (Exception ignored) {}
        }
        return list;
    }

    private List<AdminUserRecord> parseUsersFromJson(String json) {
        List<AdminUserRecord> list = new ArrayList<>();
        if (json == null || !json.contains("\"data\"")) return list;

        int dataIdx = json.indexOf("\"data\":");
        if (dataIdx == -1) return list;
        String arrayPart = json.substring(dataIdx);
        int arrStart = arrayPart.indexOf('[');
        int arrEnd = arrayPart.lastIndexOf(']');
        if (arrStart == -1 || arrEnd == -1 || arrEnd <= arrStart) return list;

        String items = arrayPart.substring(arrStart + 1, arrEnd);
        // Match user objects
        Pattern objPattern = Pattern.compile("\\{([^{}]+(?:\\{[^{}]*\\}[^{}]*)*)\\}");
        Matcher m = objPattern.matcher(items);
        while (m.find()) {
            String block = m.group(0);
            AdminUserRecord u = new AdminUserRecord();

            String idStr = extractJsonField(block, "id");
            u.id = (idStr != null && !idStr.isEmpty()) ? Integer.parseInt(idStr) : 0;
            u.login = extractJsonField(block, "login");
            u.name = extractJsonField(block, "name");
            u.email = extractJsonField(block, "email");

            String roleName = null;
            Matcher roleM = Pattern.compile("\"userRole\"\\s*:\\s*\\{[^}]*\"name\"\\s*:\\s*\"([^\"]*)\"").matcher(block);
            if (roleM.find()) {
                roleName = roleM.group(1);
            }
            if (roleName == null) roleName = extractJsonField(block, "role");
            u.role = (roleName != null) ? roleName : "User";

            u.superadmin = block.toLowerCase().contains("\"superadmin\":true") || block.toLowerCase().contains("\"superadmin\": true");

            if (u.login != null && !u.login.isEmpty()) {
                list.add(u);
            }
        }
        return list;
    }

    public static boolean isSessionVerified(String jsessionId) {
        if (jsessionId == null) return false;
        Long exp = VERIFIED_SESSIONS.get(jsessionId);
        if (exp != null && exp > System.currentTimeMillis()) {
            return true;
        }
        if (exp != null) {
            VERIFIED_SESSIONS.remove(jsessionId);
        }
        return false;
    }

    public static void markSessionVerified(String jsessionId) {
        if (jsessionId == null) return;
        VERIFIED_SESSIONS.put(jsessionId, System.currentTimeMillis() + 86_400_000L);
    }

    private String getSubPath(HttpServletRequest req) {
        String uri = req.getRequestURI();
        String ctx = req.getContextPath();
        String servletPath = req.getServletPath();
        String base = (ctx != null ? ctx : "") + (servletPath != null ? servletPath : "");
        if (uri.startsWith(base)) {
            return uri.substring(base.length());
        }
        return uri;
    }

    private String extractJSessionId(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return null;
        for (String part : cookieHeader.split(";")) {
            String p = part.trim();
            if (p.startsWith("JSESSIONID=")) {
                String val = p.substring("JSESSIONID=".length()).trim();
                if (!val.isEmpty()) return val;
            }
        }
        return null;
    }

    private HmdmUser getHmdmUser(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return null;
        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://127.0.0.1:8080/rest/private/users/current");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setRequestProperty("Cookie", cookieHeader);
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() != 200) {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
            }
            String body = sb.toString();
            if (!body.contains("\"status\":\"OK\"") || body.contains("\"data\":null")) {
                return null;
            }

            HmdmUser u = new HmdmUser();
            u.login = extractJsonField(body, "login");
            u.name = extractJsonField(body, "name");
            u.email = extractJsonField(body, "email");

            String roleName = null;
            Matcher roleM = Pattern.compile("\"userRole\"\\s*:\\s*\\{[^}]*\"name\"\\s*:\\s*\"([^\"]*)\"").matcher(body);
            if (roleM.find()) {
                roleName = roleM.group(1).trim();
            }
            // Strict default to "User" (least privilege)
            u.roleName = (roleName != null) ? roleName : "User";

            String lower = body.toLowerCase();
            u.isSuperadmin = lower.contains("\"superadmin\":true") || lower.contains("\"superadmin\": true");

            // Only users with role "Admin", "Super-Admin", or explicit "settings" admin permission can access the 2FA management menu
            boolean isExplicitAdminRole = u.roleName.equalsIgnoreCase("Admin") ||
                                          u.roleName.equalsIgnoreCase("Super-Admin") ||
                                          u.roleName.equalsIgnoreCase("Administrator");
            boolean hasSettingsPermission = lower.contains("\"name\":\"settings\"") ||
                                           lower.contains("\"name\": \"settings\"") ||
                                           lower.contains("\"permission.settings\"");

            u.isAdmin = u.isSuperadmin || isExplicitAdminRole || hasSettingsPermission;

            return u;
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private String readBody(HttpServletRequest req) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(req.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }

    private static String extractJsonField(String json, String field) {
        if (json == null) return null;
        Pattern p = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);

        Pattern pNum = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*([0-9]+)");
        Matcher mNum = pNum.matcher(json);
        if (mNum.find()) return mNum.group(1);

        return null;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
