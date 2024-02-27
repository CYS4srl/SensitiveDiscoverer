package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.http.HttpService;
import org.apache.commons.lang3.NotImplementedException;

public class HttpServiceMock implements HttpService {
    private final String host;
    private final int port;
    private final boolean secure;

    public HttpServiceMock(String host, int port, boolean secure) {
        this.host = host;
        this.port = port;
        this.secure = secure;
    }

    @Override
    public String host() {
        return this.host;
    }

    @Override
    public int port() {
        return this.port;
    }

    @Override
    public boolean secure() {
        return this.secure;
    }

    @Override
    public String ipAddress() {
        throw new NotImplementedException();
    }
}
