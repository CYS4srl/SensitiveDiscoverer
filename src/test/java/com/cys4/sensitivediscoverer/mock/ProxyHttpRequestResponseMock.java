package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.apache.commons.lang3.NotImplementedException;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.regex.Pattern;

public class ProxyHttpRequestResponseMock implements ProxyHttpRequestResponse {
    HttpRequest request;
    HttpResponse response;
    HttpService httpService;
    MimeType mimeType;

    /**
     * mock with requestUrl="https://test.com", requestHeaders=["Host: test.com"], responseHeaders=["Host: test.com","Date: $responseDate"]
     * @param requestBody
     * @param responseBody
     * @param responseDate
     * @param host
     * @param port
     * @param secure
     * @param mimeType
     */
    public ProxyHttpRequestResponseMock(String requestBody, String responseBody, String responseDate, String host, int port, boolean secure, MimeType mimeType) {
        this.httpService = new HttpServiceMock(host, port, secure);
        this.request = new HttpRequestMock(this.httpService, requestBody);
        this.response = new HttpResponseMock(responseBody, List.of(new HttpHeaderMock("Host", "test.com"), new HttpHeaderMock("Date", responseDate)));
        this.mimeType = mimeType;
    }

    /**
     * mock with url="https://test.com" and mimetype=MimeType.UNRECOGNIZED
     * @param request
     * @param response
     * @param responseDate
     */
    public ProxyHttpRequestResponseMock(String request, String response, String responseDate) {
        this(request, response, responseDate, "https://test.com", 443, true, MimeType.UNRECOGNIZED);
    }

    /**
     * mock with date="Mon, 01 Jan 1990 00:00:00 GMT", url="https://test.com" and mimetype=MimeType.UNRECOGNIZED
     * @param request
     * @param response
     */
    public ProxyHttpRequestResponseMock(String request, String response) {
        this(request, response, "Mon, 01 Jan 1990 00:00:00 GMT", "https://test.com", 443, true, MimeType.UNRECOGNIZED);
    }

    @Override
    public HttpRequest finalRequest() {
        return request;
    }

    @Override
    public HttpResponse response() {
        return response;
    }

    @Override
    public HttpService httpService() {
        return httpService;
    }

    @Override
    public MimeType mimeType() {
        return mimeType;
    }


    @Override
    public HttpRequest request() {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse originalResponse() {
        throw new NotImplementedException();
    }

    @Override
    public Annotations annotations() {
        throw new NotImplementedException();
    }

    @Override
    public String url() {
        throw new NotImplementedException();
    }

    @Override
    public String method() {
        throw new NotImplementedException();
    }

    @Override
    public String path() {
        throw new NotImplementedException();
    }

    @Override
    public String host() {
        throw new NotImplementedException();
    }

    @Override
    public int port() {
        throw new NotImplementedException();
    }

    @Override
    public boolean secure() {
        throw new NotImplementedException();
    }

    @Override
    public String httpServiceString() {
        throw new NotImplementedException();
    }

    @Override
    public String requestHttpVersion() {
        throw new NotImplementedException();
    }

    @Override
    public String requestBody() {
        throw new NotImplementedException();
    }

    @Override
    public boolean edited() {
        throw new NotImplementedException();
    }

    @Override
    public ZonedDateTime time() {
        throw new NotImplementedException();
    }

    @Override
    public int listenerPort() {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasResponse() {
        throw new NotImplementedException();
    }

    @Override
    public boolean contains(String s, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public boolean contains(Pattern pattern) {
        throw new NotImplementedException();
    }

    @Override
    public TimingData timingData() {
        throw new NotImplementedException();
    }
}
