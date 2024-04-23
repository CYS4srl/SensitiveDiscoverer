package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.persistence.Preferences;
import org.apache.commons.lang3.NotImplementedException;

import java.util.HashMap;
import java.util.Objects;
import java.util.Set;

public class PreferencesMock implements Preferences {
    HashMap<String, String> preferences = new HashMap<>();

    @Override
    public String getString(String key) {
        return preferences.get(key);
    }

    @Override
    public void setString(String key, String value) {
        preferences.put(key, value);
    }

    @Override
    public Boolean getBoolean(String key) {
        String value = preferences.get(key);
        return Objects.isNull(value) ? null : Boolean.parseBoolean(value);
    }

    @Override
    public void setBoolean(String key, boolean value) {
        preferences.put(key, String.valueOf(value));
    }

    @Override
    public Integer getInteger(String key) {
        try {
            String value = preferences.get(key);
            return Objects.isNull(value) ? null : Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public void setInteger(String key, int value) {
        preferences.put(key, String.valueOf(value));
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
