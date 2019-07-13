package com.LinLorry.Database.Security;


public interface Security extends AutoCloseable {

    long size();

    void seek(int pos);

    boolean haveNext();

    boolean hasPrevious();

    byte[] next();

    byte[] previous();

    void write(byte[] entry);

    void setSize(int size);
}
