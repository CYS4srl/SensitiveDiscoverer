package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.persistence.Preferences;
import org.apache.commons.lang3.NotImplementedException;

import java.util.Set;

public class PreferencesMock implements Preferences {
    @Override
    public String getString(String key) {
        return null;
    }

    @Override
    public void setString(String key, String value) {
    }

    @Override
    public Boolean getBoolean(String key) {
        return null;
    }

    @Override
    public void setBoolean(String key, boolean value) {
    }

    @Override
    public Integer getInteger(String key) {
        return null;
    }

    @Override
    public void setInteger(String key, int value) {
    }

    @Override
    public void deleteString(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> stringKeys() {
        throw new NotImplementedException();
    }

    @Override
    public void deleteBoolean(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> booleanKeys() {
        throw new NotImplementedException();
    }

    @Override
    public Byte getByte(String key) {
        throw new NotImplementedException();
    }

    @Override
    public void setByte(String key, byte value) {
        throw new NotImplementedException();
    }

    @Override
    public void deleteByte(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> byteKeys() {
        throw new NotImplementedException();
    }

    @Override
    public Short getShort(String key) {
        throw new NotImplementedException();
    }

    @Override
    public void setShort(String key, short value) {
        throw new NotImplementedException();
    }

    @Override
    public void deleteShort(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> shortKeys() {
        throw new NotImplementedException();
    }

    @Override
    public void deleteInteger(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> integerKeys() {
        throw new NotImplementedException();
    }

    @Override
    public Long getLong(String key) {
        throw new NotImplementedException();
    }

    @Override
    public void setLong(String key, long value) {
        throw new NotImplementedException();
    }

    @Override
    public void deleteLong(String key) {
        throw new NotImplementedException();
    }

    @Override
    public Set<String> longKeys() {
        throw new NotImplementedException();
    }
}
