package com.hmdm.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Standard RFC 6238 Time-based One-Time Password (TOTP) implementation.
 * Zero external dependencies: pure standard Java SE.
 * Compatible with Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc.
 */
public class TotpService {

    private static final String HMAC_ALGO = "HmacSHA1";
    private static final int TIME_STEP_SECONDS = 60; // 1 minute (60s) per user requirement
    private static final int CODE_DIGITS = 6;
    private static final int DIGITS_POWER = 1_000_000;
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Generates a new cryptographically random 16-character Base32 secret key (80 bits).
     */
    public static String generateSecretKey() {
        return generateSecretKey(16);
    }

    /**
     * Generates a new random Base32 secret key of specified length.
     */
    public static String generateSecretKey(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(BASE32_CHARS.charAt(RANDOM.nextInt(BASE32_CHARS.length())));
        }
        return sb.toString();
    }

    /**
     * Generates a list of single-use backup recovery codes (e.g. 5 codes, each 8 digits).
     */
    public static List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int n = 10_000_000 + RANDOM.nextInt(90_000_000);
            codes.add(String.valueOf(n));
        }
        return codes;
    }

    /**
     * Generates the standard otpauth URI used by Authenticator apps.
     * Sets period=60 so authenticator apps update the code every 1 minute.
     */
    public static String getOtpAuthUri(String issuer, String accountName, String secretKey) {
        String cleanIssuer = urlEncode(issuer);
        String cleanAccount = urlEncode(accountName);
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=60",
                cleanIssuer, cleanAccount, secretKey, cleanIssuer);
    }

    /**
     * Verifies a 6-digit TOTP code against the secret key.
     * Uses 60-second time steps (1 minute) with +/- 1 step drift window.
     * Also falls back to 30-second steps for backward compatibility with previously scanned tokens.
     */
    public static boolean verifyCode(String secretKey, String codeStr) {
        if (secretKey == null || codeStr == null) return false;
        String cleanCode = codeStr.replaceAll("\\s+", "").trim();
        if (cleanCode.length() != CODE_DIGITS) return false;

        int userCode;
        try {
            userCode = Integer.parseInt(cleanCode);
        } catch (NumberFormatException e) {
            return false;
        }

        byte[] keyBytes = decodeBase32(secretKey);
        if (keyBytes.length == 0) return false;

        long currentUnixTime = System.currentTimeMillis() / 1000L;

        // Primary: 60-second time step (1 minute)
        long currentCounter60 = currentUnixTime / 60L;
        for (int delta = -1; delta <= 1; delta++) {
            long counter = currentCounter60 + delta;
            int generated = generateTotp(keyBytes, counter);
            if (generated == userCode) {
                return true;
            }
        }

        // Fallback: 30-second time step (for backward compatibility)
        long currentCounter30 = currentUnixTime / 30L;
        for (int delta = -1; delta <= 1; delta++) {
            long counter = currentCounter30 + delta;
            int generated = generateTotp(keyBytes, counter);
            if (generated == userCode) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculates the TOTP code for a specific counter step.
     */
    private static int generateTotp(byte[] keyBytes, long counter) {
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGO));
            byte[] hash = mac.doFinal(data);

            // Dynamic truncation (RFC 4226)
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            return binary % DIGITS_POWER;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Decodes a Base32 string into byte array.
     */
    public static byte[] decodeBase32(String base32) {
        if (base32 == null) return new byte[0];
        String clean = base32.toUpperCase().replaceAll("[^A-Z2-7]", "");
        if (clean.isEmpty()) return new byte[0];

        int totalBits = clean.length() * 5;
        byte[] result = new byte[totalBits / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int resultIndex = 0;

        for (int i = 0; i < clean.length(); i++) {
            int val = BASE32_CHARS.indexOf(clean.charAt(i));
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                if (resultIndex < result.length) {
                    result[resultIndex++] = (byte) ((buffer >> bitsLeft) & 0xFF);
                }
            }
        }
        return (resultIndex == result.length) ? result : Arrays.copyOf(result, resultIndex);
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }
}
