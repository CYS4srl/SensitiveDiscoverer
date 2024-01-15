package com.cys4.sensitivediscoverer.mock;

import burp.IHttpService;

public class HttpServiceMock implements IHttpService {

    @Override
    public String getHost() {
        return "test.com";
    }

    @Override
    public int getPort() {
        return 443;
    }

    @Override
    public String getProtocol() {
        return "https";
    }
}
