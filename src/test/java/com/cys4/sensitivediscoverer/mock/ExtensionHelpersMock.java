package com.cys4.sensitivediscoverer.mock;

import burp.*;
import org.apache.commons.lang3.NotImplementedException;

import java.net.URL;
import java.util.List;
import java.util.function.Function;

public class ExtensionHelpersMock implements IExtensionHelpers {
    Function<IHttpRequestResponse, IRequestInfo> analyzeRequestFunction;
    Function<byte[], IResponseInfo> analyzeResponseFunction;
    Function<byte[], String> bytesToStringFunction;

    @Override
    public IRequestInfo analyzeRequest(IHttpRequestResponse iHttpRequestResponse) {
        return analyzeRequestFunction.apply(iHttpRequestResponse);
    }

    public void setAnalyzeRequestFunction(Function<IHttpRequestResponse, IRequestInfo> analyzeRequestFunction) {
        this.analyzeRequestFunction = analyzeRequestFunction;
    }

    @Override
    public IResponseInfo analyzeResponse(byte[] bytes) {
        return analyzeResponseFunction.apply(bytes);
    }

    public void setAnalyzeResponseFunction(Function<byte[], IResponseInfo> analyzeResponseFunction) {
        this.analyzeResponseFunction = analyzeResponseFunction;
    }

    @Override
    public String bytesToString(byte[] bytes) {
        return bytesToStringFunction.apply(bytes);
    }

    public void setBytesToStringFunction(Function<byte[], String> bytesToStringFunction) {
        this.bytesToStringFunction = bytesToStringFunction;
    }


    @Override
    public IRequestInfo analyzeRequest(IHttpService iHttpService, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IRequestInfo analyzeRequest(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IParameter getRequestParameter(byte[] bytes, String s) {
        throw new NotImplementedException();
    }

    @Override
    public String urlDecode(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String urlEncode(String s) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] urlDecode(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] urlEncode(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] base64Decode(String s) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] base64Decode(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public String base64Encode(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String base64Encode(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] stringToBytes(String s) {
        throw new NotImplementedException();
    }

    @Override
    public int indexOf(byte[] bytes, byte[] bytes1, boolean b, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] buildHttpMessage(List<String> list, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] buildHttpRequest(URL url) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] addParameter(byte[] bytes, IParameter iParameter) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] removeParameter(byte[] bytes, IParameter iParameter) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] updateParameter(byte[] bytes, IParameter iParameter) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] toggleRequestMethod(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpService buildHttpService(String s, int i, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpService buildHttpService(String s, int i, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public IParameter buildParameter(String s, String s1, byte b) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpHeader buildHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public IScannerInsertionPoint makeScannerInsertionPoint(String s, byte[] bytes, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public IResponseVariations analyzeResponseVariations(byte[]... bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IResponseKeywords analyzeResponseKeywords(List<String> list, byte[]... bytes) {
        throw new NotImplementedException();
    }
}
