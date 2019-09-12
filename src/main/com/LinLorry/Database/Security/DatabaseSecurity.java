package com.LinLorry.Database.Security;

import com.LinLorry.Database.until.MD5Tool;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.ByteBuffer;


public class DatabaseSecurity implements Security {
    private static final Cipher cipher;

    private int headerLength;

    private final DatabaseSecurityHeader header;
    private final DatabaseSecurityContent content;
    private final String filename;


    static {
        try {
            cipher = Cipher.getInstance(DatabaseSecurityHeader.ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public DatabaseSecurity(String filename, String password) throws IOException {
        this.filename = filename;
        byte[] headerBytes = verifyFile();
        headerLength = headerBytes.length;

        header = new DatabaseSecurityHeader(headerBytes, MD5Tool.getMD5Bytes(password));
        content = new DatabaseSecurityContent(filename);
    }

    private byte[] verifyFile() {
        byte[] headerLengthBytes = new byte[4];
        byte[] headerBytes;
        try {
            File file = new File(filename);
            FileInputStream inputStream = new FileInputStream(file.getAbsoluteFile());

            if (inputStream.read(headerLengthBytes) != 4) {
                throw new RuntimeException("DB file error! Don't have headerLength!");
            }

            int headerLength = ByteBuffer.wrap(headerLengthBytes).getInt();
            headerBytes = new byte[headerLength];
            if (inputStream.read(headerBytes) != headerLength) {
                throw new RuntimeException("DB file error! Header incomplete!");
            }

            byte[] md5 = new byte[32];
            byte[] contentBytes = new byte[1024];
            int readLength;
            while (inputStream.read(md5) == 32) {
                readLength = inputStream.read(contentBytes);
                if (readLength == -1) {
                    throw new RuntimeException("DB file error! Content incomplete!");
                }

                if (readLength == 1024) {
                    if (MD5Tool.verify(contentBytes, md5)) {
                        throw new RuntimeException("DB file error! Content have error!");
                    }
                } else {
                    byte[] contentBytesTmp = new byte[readLength];
                    System.arraycopy(contentBytes, 0, contentBytesTmp, 0, readLength);
                    if (MD5Tool.verify(contentBytesTmp, md5)) {
                        throw new RuntimeException("DB file error! Content have error!");
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return headerBytes;
    }

    public static void create(String filename, String password) {
        File file = new File(filename);

        if (file.exists()) {
            throw new RuntimeException("DB file is exists");
        }

        try {
            if (!file.createNewFile()) {
                throw new RuntimeException("Create DB file failed");
            }

            byte[] headerBytes = DatabaseSecurityHeader.generateHeader(password);
            int headerBytesLength = headerBytes.length;

            try (FileOutputStream fileOutputStream = new FileOutputStream(file.getAbsoluteFile())) {
                fileOutputStream.write(ByteBuffer.allocate(4).putInt(headerBytesLength).array());
                fileOutputStream.write(headerBytes);
                fileOutputStream.write(ByteBuffer.allocate(4).putInt(0).array());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void updatePassword(String password) throws IOException {
        byte[] headerBytes = header.updatePassword(password);
        headerLength = headerBytes.length;

        try (FileOutputStream fileOutputStream = new FileOutputStream(filename)) {
            fileOutputStream.write(ByteBuffer.allocate(4).putInt(headerLength).array());
            fileOutputStream.write(headerBytes);
        }
    }

    @Override
    public long size() {
        return  content.size();
    }

    @Override
    public void seek(int pos) {
        content.seek(pos);
    }

    @Override
    public boolean haveNext() {
        return content.hasNext();
    }

    @Override
    public byte[] next() {
        return decrypt(content.next());
    }

    @Override
    public boolean hasPrevious() {
        return content.hasPrevious();
    }

    @Override
    public byte[] previous() {
        return decrypt(content.previous());
    }

    @Override
    public void write(byte[] entry) {
        content.set(encrypt(entry));
        content.next();
    }

    @Override
    public void setSize(int size) {
        content.setSize(size);
    }

    @Override
    public void close() throws IOException {
        try (RandomAccessFile randomAccessFile = new RandomAccessFile(filename, "rw")) {
            randomAccessFile.skipBytes(4 + headerLength);
            randomAccessFile.write(content.getBytes());
            randomAccessFile.setLength(randomAccessFile.getFilePointer());
        }
    }

    private byte[] encrypt(byte[] unencrypted) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, header.getPublicKey());
            return cipher.doFinal(unencrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private byte[] decrypt(byte[] encrypted) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, header.getPrivateKey());
            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
