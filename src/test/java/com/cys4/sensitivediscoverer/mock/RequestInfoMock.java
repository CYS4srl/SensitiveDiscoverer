package com.cys4.sensitivediscoverer.mock;

import burp.IParameter;
import burp.IRequestInfo;

import java.net.URL;
import java.util.List;

public class RequestInfoMock implements IRequestInfo {
    List<String> headers;
    URL url;

    public RequestInfoMock(List<String> headers, URL url) {
        this.headers = headers;
        this.url = url;
    }

    @Override
    public URL getUrl() {
        return this.url;
    }

    @Override
    public List<String> getHeaders() {
        return this.headers;
    }

    @Override
    public int getBodyOffset() {
        // request only contains the body. The headers are set manually
        return 0;
    }

    @Override
    public byte getContentType() {
        // don't care
        return 0;
    }

    @Override
    public String getMethod() {
        // don't care
        return null;
    }

    @Override
    public List<IParameter> getParameters() {
        // don't care
        return null;
    }
}
