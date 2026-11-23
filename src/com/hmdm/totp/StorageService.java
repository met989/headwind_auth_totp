package com.hmdm.totp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Thread-safe persistence service for Headwind 2FA/TOTP credentials and user configuration.
 * Zero external dependencies: pure standard Java.
 * Stores configuration in a clean JSON file with atomic write semantics.
 */
public class StorageService {

    private static final String[] CANDIDATE_PATHS = new String[] {
            System.getProperty("headwind.totp.config"),
            "/etc/tomcat10/Catalina/headwind-totp.json",
            "/var/lib/tomcat10/conf/headwind-totp.json",
            "/var/lib/tomcat9/conf/headwind-totp.json",
            "/etc/headwind-totp/config.json",
            "/tmp/headwind-totp.json"
    };

    private static volatile File activeStorageFile = null;
    private static final Object FILE_LOCK = new Object();

    // Cache: username -> UserRecord
    private static final ConcurrentHashMap<String, UserRecord> USER_CACHE = new ConcurrentHashMap<>();
    private static volatile boolean isLoaded = false;

    public static class UserRecord {
        public String username;
        public String secret;
        public long createdAt;
        public List<String> backupCodes = new ArrayList<>();
        public boolean enabled = false; // Default: 2FA is DISABLED

        public UserRecord(String username) {
            this.username = username;
            this.secret = "";
            this.createdAt = System.currentTimeMillis();
            this.enabled = false;
        }

        public UserRecord(String username, String secret, List<String> backupCodes, boolean enabled) {
            this.username = username;
            this.secret = (secret != null) ? secret : "";
            this.createdAt = System.currentTimeMillis();
            if (backupCodes != null) this.backupCodes.addAll(backupCodes);
            this.enabled = enabled;
        }

        public boolean isConfigured() {
            return secret != null && !secret.trim().isEmpty();
        }
    }

    public static File getStorageFile() {
        if (activeStorageFile != null && activeStorageFile.exists() && activeStorageFile.canRead()) {
            return activeStorageFile;
        }
        for (String p : CANDIDATE_PATHS) {
            if (p != null && !p.trim().isEmpty()) {
                File f = new File(p);
                if (f.exists() && f.canRead()) {
                    activeStorageFile = f;
                    return f;
                }
            }
        }
        File def = new File("/etc/tomcat10/Catalina/headwind-totp.json");
        activeStorageFile = def;
        return def;
    }

    public static synchronized void ensureLoaded() {
        if (isLoaded) return;
        reload();
        isLoaded = true;
    }

    public static synchronized void reload() {
        USER_CACHE.clear();
        File f = getStorageFile();
        if (!f.exists() || !f.canRead()) return;

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            parseJson(sb.toString());
        } catch (Exception e) {
            System.err.println("[Headwind-TOTP] Error reading storage file " + f.getAbsolutePath() + ": " + e.getMessage());
        }
    }

    public static UserRecord getUserRecord(String username) {
        if (username == null) return null;
        ensureLoaded();
        return USER_CACHE.get(username.toLowerCase().trim());
    }

    public static boolean isUserEnabled(String username) {
        if (username == null) return false;
        ensureLoaded();
        UserRecord rec = USER_CACHE.get(username.toLowerCase().trim());
        return rec != null && rec.enabled;
    }

    public static boolean isUserConfigured(String username) {
        if (username == null) return false;
        ensureLoaded();
        UserRecord rec = USER_CACHE.get(username.toLowerCase().trim());
        return rec != null && rec.isConfigured();
    }

    public static boolean hasTotp(String username) {
        return isUserConfigured(username);
    }

    public static String getSecret(String username) {
        UserRecord rec = getUserRecord(username);
        return (rec != null && rec.isConfigured()) ? rec.secret : null;
    }

    public static synchronized void setUserEnabled(String username, boolean enabled) throws IOException {
        if (username == null) return;
        ensureLoaded();
        String u = username.toLowerCase().trim();
        UserRecord rec = USER_CACHE.get(u);
        if (rec == null) {
            rec = new UserRecord(u);
            rec.enabled = enabled;
            USER_CACHE.put(u, rec);
        } else {
            rec.enabled = enabled;
        }
        persist();
    }

    public static synchronized void saveUser(String username, String secret, List<String> backupCodes) throws IOException {
        if (username == null || secret == null) return;
        ensureLoaded();
        String u = username.toLowerCase().trim();
        UserRecord rec = USER_CACHE.get(u);
        if (rec == null) {
            rec = new UserRecord(u, secret, backupCodes, true);
            USER_CACHE.put(u, rec);
        } else {
            rec.secret = secret;
            rec.backupCodes.clear();
            if (backupCodes != null) rec.backupCodes.addAll(backupCodes);
            rec.enabled = true;
            rec.createdAt = System.currentTimeMillis();
        }
        persist();
    }

    public static synchronized boolean resetUser(String username) throws IOException {
        if (username == null) return false;
        ensureLoaded();
        String u = username.toLowerCase().trim();
        UserRecord rec = USER_CACHE.get(u);
        if (rec != null) {
            rec.secret = "";
            rec.backupCodes.clear();
            rec.createdAt = System.currentTimeMillis();
            persist();
            return true;
        }
        return false;
    }

    public static synchronized boolean deleteUserRecord(String username) throws IOException {
        if (username == null) return false;
        ensureLoaded();
        String u = username.toLowerCase().trim();
        UserRecord removed = USER_CACHE.remove(u);
        persist();
        return removed != null;
    }

    public static synchronized boolean consumeBackupCode(String username, String code) throws IOException {
        if (username == null || code == null) return false;
        ensureLoaded();
        UserRecord rec = getUserRecord(username);
        if (rec == null || rec.backupCodes == null) return false;

        String clean = code.replaceAll("[^0-9]", "").trim();
        Iterator<String> it = rec.backupCodes.iterator();
        while (it.hasNext()) {
            String b = it.next().trim();
            if (b.equals(clean)) {
                it.remove();
                persist();
                return true;
            }
        }
        return false;
    }

    public static Set<String> listUsers() {
        ensureLoaded();
        return Collections.unmodifiableSet(USER_CACHE.keySet());
    }

    private static void persist() throws IOException {
        synchronized (FILE_LOCK) {
            File target = getStorageFile();
            File parent = target.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            File temp = File.createTempFile("hmdm-totp-", ".tmp");
            try {
                try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(temp), StandardCharsets.UTF_8))) {
                    out.println("{");
                    out.println("  \"users\": {");
                    int i = 0;
                    int total = USER_CACHE.size();
                    for (Map.Entry<String, UserRecord> entry : USER_CACHE.entrySet()) {
                        i++;
                        UserRecord r = entry.getValue();
                        out.println("    \"" + escapeJson(r.username) + "\": {");
                        out.println("      \"secret\": \"" + escapeJson(r.secret) + "\",");
                        out.println("      \"created_at\": " + r.createdAt + ",");
                        out.println("      \"enabled\": " + r.enabled + ",");
                        out.print("      \"backup_codes\": [");
                        for (int j = 0; j < r.backupCodes.size(); j++) {
                            out.print("\"" + escapeJson(r.backupCodes.get(j)) + "\"");
                            if (j < r.backupCodes.size() - 1) out.print(", ");
                        }
                        out.println("]");
                        out.println("    }" + (i < total ? "," : ""));
                    }
                    out.println("  }");
                    out.println("}");
                }

                try (FileInputStream in = new FileInputStream(temp); FileOutputStream out = new FileOutputStream(target, false)) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                    }
                    out.flush();
                }
            } finally {
                if (temp.exists()) temp.delete();
            }
        }
    }

    private static void parseJson(String json) {
        if (json == null || json.trim().isEmpty()) return;

        Pattern userBlockPattern = Pattern.compile("\"([a-zA-Z0-9_.@\\-]+)\"\\s*:\\s*\\{([^}]+)\\}");
        Matcher m = userBlockPattern.matcher(json);
        while (m.find()) {
            String uname = m.group(1).trim().toLowerCase();
            String block = m.group(2);

            String secret = "";
            long createdAt = System.currentTimeMillis();
            boolean enabled = false;
            List<String> backupCodes = new ArrayList<>();

            Matcher secM = Pattern.compile("\"secret\"\\s*:\\s*\"([^\"]*)\"").matcher(block);
            if (secM.find()) secret = secM.group(1).trim();

            Matcher crM = Pattern.compile("\"created_at\"\\s*:\\s*([0-9]+)").matcher(block);
            if (crM.find()) createdAt = Long.parseLong(crM.group(1));

            Matcher enM = Pattern.compile("\"enabled\"\\s*:\\s*(true|false)").matcher(block);
            if (enM.find()) enabled = Boolean.parseBoolean(enM.group(1));

            Matcher bcM = Pattern.compile("\"backup_codes\"\\s*:\\s*\\[([^\\]]*)\\]").matcher(block);
            if (bcM.find()) {
                String arr = bcM.group(1);
                Matcher codeM = Pattern.compile("\"([^\"]+)\"").matcher(arr);
                while (codeM.find()) {
                    backupCodes.add(codeM.group(1).trim());
                }
            }

            UserRecord rec = new UserRecord(uname, secret, backupCodes, enabled);
            rec.createdAt = createdAt;
            USER_CACHE.put(uname, rec);
        }
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
