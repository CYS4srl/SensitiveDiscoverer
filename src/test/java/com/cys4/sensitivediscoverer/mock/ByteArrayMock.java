package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import org.apache.commons.lang3.NotImplementedException;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.regex.Pattern;

public class ByteArrayMock implements ByteArray {
    private final String data;

    public ByteArrayMock(String data) {
        this.data = data;
    }

    @Override
    public byte[] getBytes() {
        return data.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte getByte(int i) {
        throw new NotImplementedException();
    }

    @Override
    public void setByte(int i, byte b) {
        throw new NotImplementedException();
    }

    @Override
    public void setByte(int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public void setBytes(int i, byte... bytes) {
        throw new NotImplementedException();
    }

    @Override
    public void setBytes(int i, int... ints) {
        throw new NotImplementedException();
    }

    @Override
    public void setBytes(int i, ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public int length() {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray subArray(int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray subArray(Range range) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray copy() {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray copyToTempFile() {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(String s) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(ByteArray byteArray, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(String s, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(ByteArray byteArray, boolean b, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(String s, boolean b, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(Pattern pattern) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(Pattern pattern, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(String s) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(ByteArray byteArray, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(String s, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(ByteArray byteArray, boolean b, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(String s, boolean b, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(Pattern pattern) {
        throw new NotImplementedException();
    }

    @Override
    public int countMatches(Pattern pattern, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray withAppended(byte... bytes) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray withAppended(int... ints) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray withAppended(String s) {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray withAppended(ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public Iterator<Byte> iterator() {
        throw new NotImplementedException();
    }
}
