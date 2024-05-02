package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import org.apache.commons.lang3.NotImplementedException;

public class PersistenceMock implements Persistence {
    private final Preferences preferences = new PreferencesMock();

    @Override
    public Preferences preferences() {
        return this.preferences;
    }

    @Override
    public PersistedObject extensionData() {
        throw new NotImplementedException();
    }
}
