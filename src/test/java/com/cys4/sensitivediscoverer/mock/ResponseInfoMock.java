package com.cys4.sensitivediscoverer.mock;

import burp.ICookie;
import burp.IResponseInfo;

import java.util.List;

public class ResponseInfoMock implements IResponseInfo {
    List<String> headers;

    public ResponseInfoMock(List<String> headers) {
        this.headers = headers;
    }

    @Override
    public List<String> getHeaders() {
        return this.headers;
    }

    @Override
    public int getBodyOffset() {
        // response only contains the body. The headers are set manually
        return 0;
    }

    @Override
    public short getStatusCode() {
        // don't care
        return 200;
    }

    @Override
    public List<ICookie> getCookies() {
        // don't care
        return null;
    }

    @Override
    public String getStatedMimeType() {
        // don't care
        return "TEST";
    }

    @Override
    public String getInferredMimeType() {
        // don't care
        return "TEST";
    }
}
