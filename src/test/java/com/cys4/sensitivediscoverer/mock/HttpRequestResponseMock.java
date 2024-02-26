package com.cys4.sensitivediscoverer.mock;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import org.apache.commons.lang3.NotImplementedException;

public class HttpRequestResponseMock implements IHttpRequestResponse {
    byte[] request;
    byte[] response;
    IHttpService httpServiceMock = new HttpServiceMock();

    public HttpRequestResponseMock(byte[] request, byte[] response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpServiceMock;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.httpServiceMock = iHttpService;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public String getComment() {
        throw new NotImplementedException();
    }

    @Override
    public void setComment(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String getHighlight() {
        throw new NotImplementedException();
    }

    @Override
    public void setHighlight(String s) {
        throw new NotImplementedException();
    }
}
