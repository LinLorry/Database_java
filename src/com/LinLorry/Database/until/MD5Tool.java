package com.LinLorry.Database.until;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MD5Tool {
    private static final String MD5 = "MD5";
    private static final MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance(MD5);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getMD5String(String s) {
        return getMD5String(s.getBytes(StandardCharsets.UTF_8));
    }

    public static String getMD5String(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder(32);
        md.update(bytes);
        String md5Code = new BigInteger(1, md.digest()).toString(16);
        for (int i = 0; i < 32 - md5Code.length(); ++i) {
            stringBuilder.append('0');
        }
        stringBuilder.append(md5Code);
        return stringBuilder.toString();
    }

    public static byte[] getMD5Bytes(String s) {
        return getMD5Bytes(s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] getMD5Bytes(byte[] bytes) {
        return md.digest(bytes);
    }

    public static boolean verify(String s, String md5String) {
        return getMD5String(s).equals(md5String);
    }

    public static boolean verify(byte[] bytes, byte[] md5bytes) {
        return Arrays.equals(getMD5Bytes(bytes), md5bytes);
    }

}
