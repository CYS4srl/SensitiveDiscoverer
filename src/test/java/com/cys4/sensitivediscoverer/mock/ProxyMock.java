package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.*;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import org.apache.commons.lang3.NotImplementedException;

import java.util.List;

public class ProxyMock implements Proxy {
    private List<ProxyHttpRequestResponse> proxyHistory;

    @Override
    public List<ProxyHttpRequestResponse> history() {
        return proxyHistory;
    }

    public void setHistory(List<ProxyHttpRequestResponse> proxyHistory) {
        this.proxyHistory = proxyHistory;
    }

    @Override
    public void enableIntercept() {
        throw new NotImplementedException();
    }

    @Override
    public void disableIntercept() {
        throw new NotImplementedException();
    }

    @Override
    public List<ProxyHttpRequestResponse> history(ProxyHistoryFilter proxyHistoryFilter) {
        throw new NotImplementedException();
    }

    @Override
    public List<ProxyWebSocketMessage> webSocketHistory() {
        throw new NotImplementedException();
    }

    @Override
    public List<ProxyWebSocketMessage> webSocketHistory(ProxyWebSocketHistoryFilter proxyWebSocketHistoryFilter) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerRequestHandler(ProxyRequestHandler proxyRequestHandler) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerResponseHandler(ProxyResponseHandler proxyResponseHandler) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerWebSocketCreationHandler(ProxyWebSocketCreationHandler proxyWebSocketCreationHandler) {
        throw new NotImplementedException();
    }
}
