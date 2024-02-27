package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import org.apache.commons.lang3.NotImplementedException;

public class ExtensionMock implements Extension {
    @Override
    public void setName(String s) {
    }

    @Override
    public String filename() {
        throw new NotImplementedException();
    }

    @Override
    public boolean isBapp() {
        return true;
    }

    @Override
    public void unload() {
    }

    @Override
    public Registration registerUnloadingHandler(ExtensionUnloadingHandler extensionUnloadingHandler) {
        throw new NotImplementedException();
    }
}
