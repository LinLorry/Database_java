package com.LinLorry.Database.Security;

import com.LinLorry.Database.until.MD5Tool;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

public class DatabaseSecurityHeader {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public static final String ALGORITHM = "RSA";
    private static final KeyFactory RSAKeyFactory;

    static {
        try {
            RSAKeyFactory = KeyFactory.getInstance(ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public DatabaseSecurityHeader(byte[] headerBytes, byte[] passwordMD5) {
        byte[] indexBytes = new byte[4];
        System.arraycopy(headerBytes, 0, indexBytes, 0, 4);
        int index = ByteBuffer.wrap(indexBytes).getInt();

        LinkedList<Byte> linkedList = new LinkedList<>();
        for (int i = 4; i < headerBytes.length; ++i) {
            linkedList.add(headerBytes[i]);
        }

        ListIterator listIterator = linkedList.listIterator(index);

        for (int i = passwordMD5.length - 1; i > 0; i -= 2) {
            if (!listIterator.previous().equals(passwordMD5[i])) {
                throw new RuntimeException();
            }

            listIterator.remove();

            for (int j = 0; j < (passwordMD5[i - 1] & 0xff) && i != 1; ++j) {

                if (listIterator.hasPrevious()) {
                    listIterator.previous();
                } else {
                    listIterator = linkedList.listIterator(linkedList.size());
                }
            }
        }

        listIterator = linkedList.listIterator();

        byte[] privateKeyBytesLengthBytes = new byte[4];
        byte[] publicKeyBytesLengthBytes = new byte[4];

        for (int i = 0; i < 4; i++) {
            privateKeyBytesLengthBytes[i] = (byte) listIterator.next();
        }
        for (int i = 0; i < 4; i++) {
            publicKeyBytesLengthBytes[i] = (byte) listIterator.next();
        }

        int privateKeyBytesLength = ByteBuffer.wrap(privateKeyBytesLengthBytes).getInt();
        int publicKeyBytesLength = ByteBuffer.wrap(publicKeyBytesLengthBytes).getInt();

        List<Byte> privateKeyList = linkedList.subList(8, privateKeyBytesLength + 8);
        List<Byte> publicKeyList = linkedList.subList(privateKeyBytesLength + 8,
                privateKeyBytesLength + 8 + publicKeyBytesLength);

        try {
            setPrivateKey(privateKeyList);
            setPublicKey(publicKeyList);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] generateHeader(String password) {
        KeyPairGenerator keyPairGenerator;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        LinkedList<Byte> linkedList = getKeyByteLinkedList(privateKey, publicKey);

        confusionByteLinkedList(linkedList, MD5Tool.getMD5Bytes(password));

        return transformHeaderLinkedListToHeaderBytes(linkedList);
    }

    public byte[] updatePassword(String password) {
        LinkedList<Byte> linkedList = getKeyByteLinkedList(privateKey, publicKey);
        confusionByteLinkedList(linkedList, MD5Tool.getMD5Bytes(password));
        return transformHeaderLinkedListToHeaderBytes(linkedList);

    }

    private static LinkedList<Byte> getKeyByteLinkedList(PrivateKey privateKey, PublicKey publicKey) {
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] publicKeyBytes = publicKey.getEncoded();

        LinkedList<Byte> linkedList = new LinkedList<>();

        for (byte b : ByteBuffer.allocate(4).putInt(privateKeyBytes.length).array()) {
            linkedList.add(b);
        }

        for (byte b : ByteBuffer.allocate(4).putInt(publicKeyBytes.length).array()) {
            linkedList.add(b);
        }

        for (byte b : privateKeyBytes) {
            linkedList.add(b);
        }

        for (byte b : publicKeyBytes) {
            linkedList.add(b);
        }

        return linkedList;
    }

    private static void confusionByteLinkedList(LinkedList<Byte> linkedList, byte[] confusion) {
        ListIterator<Byte> listIterator = linkedList.listIterator();

        for (int i = 0; i < confusion.length; i += 2) {
            for (int j = 0; j < (confusion[i] & 0xff); ++j) {
                if (listIterator.hasNext()) {
                    listIterator.next();
                } else {
                    listIterator = linkedList.listIterator();
                }
            }
            listIterator.add(confusion[i+1]);
        }

        byte[] indexBytes = ByteBuffer.allocate(4).putInt(listIterator.nextIndex()).array();

        for (int i = 3; i >= 0; --i) {
            linkedList.push(indexBytes[i]);
        }
    }

    private static byte[] transformHeaderLinkedListToHeaderBytes(LinkedList<Byte> linkedList) {
        int index = 0;
        byte[] headerBytes =  new byte[linkedList.size()];

        for (Byte b : linkedList) {
            headerBytes[index++] = b;
        }

        return headerBytes;
    }

    private void setPublicKey(List<Byte> publicKeyList)
            throws InvalidKeySpecException {
        byte[] publicKeyBytes = new byte[publicKeyList.size()];
        int index = 0;
        for (byte b : publicKeyList) {
            publicKeyBytes[index++] = b;
        }

        publicKey = RSAKeyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    private void setPrivateKey(List<Byte> privateKeyList)
            throws InvalidKeySpecException {
        byte[] privateKeyBytes = new byte[privateKeyList.size()];
        int index = 0;
        for (byte b : privateKeyList) {
            privateKeyBytes[index++] = b;
        }

        privateKey = RSAKeyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
