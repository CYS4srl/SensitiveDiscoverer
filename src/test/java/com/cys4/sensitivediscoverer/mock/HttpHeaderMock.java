package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.http.message.HttpHeader;

public class HttpHeaderMock implements HttpHeader {
    private final String name;
    private final String value;

    public HttpHeaderMock(String name, String value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public String name() {
        return this.name;
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public String toString() {
        return name + ": " + value;
    }
}
