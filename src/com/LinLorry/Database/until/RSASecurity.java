package com.LinLorry.Database.until;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSASecurity {
    private static final Cipher cipher;

    private static final String RSA_ALGORITHM = "RSA";

    static {
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(PublicKey publicKey, String unencrypted) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(unencrypted.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static String decrypt(PrivateKey privateKey, byte[] encrypted) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
