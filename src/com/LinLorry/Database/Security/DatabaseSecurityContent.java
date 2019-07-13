package com.LinLorry.Database.Security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class DatabaseSecurityContent {
    private int location = 0;
    private int size;
    private byte[][] content;

    public DatabaseSecurityContent(String filename) throws IOException {
        File file = new File(filename);

        try (FileInputStream fileInputStream = new FileInputStream(file.getAbsoluteFile())) {
            byte[] lengthBytes = new byte[4];

            if (fileInputStream.read(lengthBytes) != 4) {
                throw new RuntimeException("DB file error! Don't have headerLength!");
            }

            int headerLength = ByteBuffer.wrap(lengthBytes).getInt();

            if (fileInputStream.skip(headerLength) != headerLength) {
                throw new RuntimeException("DB file error! Header length error!");
            }

            if (fileInputStream.read(lengthBytes) != 4) {
                throw new RuntimeException("DB file error! Content size error!");
            }

            size = ByteBuffer.wrap(lengthBytes).getInt();

            if (size == 0) {
                content = new byte[32][];
            } else {
                content = new byte[size * 2][];
            }


            while (fileInputStream.read(lengthBytes) == 4) {
                if (location == size) {
                    throw new RuntimeException("DB file error! Size error!");
                }
                content[location] = new byte[ByteBuffer.wrap(lengthBytes).getInt()];
                if (fileInputStream.read(content[location]) != content[location].length) {
                    throw new RuntimeException("Read data error!");
                }
                location++;
            }

            location = 0;
        }
    }

    public int size() {
        return size;
    }

    public void seek(int pos) {
        if (pos < 0 || pos > size) {
            throw new ArrayIndexOutOfBoundsException();
        }
        location = pos;
    }

    public boolean hasNext() {
        return location != size;
    }

    public byte[] next() {
        if (!hasNext()) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return content[location++];
    }

    public boolean hasPrevious() {
        return location != 0;
    }

    public byte[] previous() {
        if (!hasPrevious()) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return content[--location];
    }

    public void set(byte[] data) {
        if (!hasNext()) {
            if (size == content.length) {
                byte[][] tmp = new byte[content.length * 2][];
                System.arraycopy(content, 0, tmp, 0, content.length);
                content = tmp;
            }
            size++;
        }
        content[location] = data;
    }

    public void setSize(int size) {
        if (size > this.size) {
            throw new RuntimeException("Set null size");
        }
        this.size = size;
        if (location >= size) {
            location = size;
        }
    }

    public byte[] getBytes() {

        int length = 4 + size * 4;

        for (int i = 0; i < size; ++i) {
            length += content[i].length;
        }

        byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();

        byte[] result = new byte[length];
        System.arraycopy(sizeBytes, 0, result, 0, 4);

        int index = 4;

        for (int i = 0; i < size; ++i) {
            System.arraycopy(ByteBuffer.allocate(4).putInt(content[i].length).array(),
                    0, result, index, 4);
            index += 4;
            System.arraycopy(content[i], 0, result, index, content[i].length);
            index += content[i].length;
        }

        return result;
    }
}
