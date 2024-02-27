package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import org.apache.commons.lang3.NotImplementedException;

import java.util.List;
import java.util.regex.Pattern;

public class HttpRequestMock implements HttpRequest {
    private final String body;
    private final HttpService httpService;
    private final List<HttpHeader> headers;

    public HttpRequestMock(HttpService httpService, String body, List<HttpHeader> headers) {
        this.httpService = httpService;
        this.body = body;
        this.headers = headers;
    }

    public HttpRequestMock(HttpService httpService, String body) {
        this(httpService, body, List.of(new HttpHeaderMock("Host", "test.com")));
    }

    @Override
    public String url() {
        return "https://test.com";
    }

    @Override
    public List<HttpHeader> headers() {
        return this.headers;
    }

    @Override
    public String bodyToString() {
        return body;
    }

    @Override
    public boolean isInScope() {
        throw new NotImplementedException();
    }

    @Override
    public HttpService httpService() {
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
    public String query() {
        throw new NotImplementedException();
    }

    @Override
    public String pathWithoutQuery() {
        throw new NotImplementedException();
    }

    @Override
    public String fileExtension() {
        throw new NotImplementedException();
    }

    @Override
    public ContentType contentType() {
        throw new NotImplementedException();
    }

    @Override
    public List<ParsedHttpParameter> parameters() {
        throw new NotImplementedException();
    }

    @Override
    public List<ParsedHttpParameter> parameters(HttpParameterType httpParameterType) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasParameters() {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasParameters(HttpParameterType httpParameterType) {
        throw new NotImplementedException();
    }

    @Override
    public ParsedHttpParameter parameter(String s, HttpParameterType httpParameterType) {
        throw new NotImplementedException();
    }

    @Override
    public String parameterValue(String s, HttpParameterType httpParameterType) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasParameter(String s, HttpParameterType httpParameterType) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasParameter(HttpParameter httpParameter) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasHeader(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpHeader header(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String headerValue(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String httpVersion() {
        throw new NotImplementedException();
    }

    @Override
    public int bodyOffset() {
        throw new NotImplementedException();
    }

    @Override
    public ByteArray body() {
        throw new NotImplementedException();
    }

    @Override
    public List<Marker> markers() {
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
    public ByteArray toByteArray() {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest copyToTempFile() {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withService(HttpService httpService) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withPath(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withMethod(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withParameter(HttpParameter httpParameter) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withAddedParameters(List<? extends HttpParameter> list) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withAddedParameters(HttpParameter... httpParameters) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withRemovedParameters(List<? extends HttpParameter> list) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withRemovedParameters(HttpParameter... httpParameters) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withUpdatedParameters(List<? extends HttpParameter> list) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withUpdatedParameters(HttpParameter... httpParameters) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withTransformationApplied(HttpTransformation httpTransformation) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withBody(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withBody(ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withAddedHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withAddedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withUpdatedHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withUpdatedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withRemovedHeader(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withRemovedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withMarkers(List<Marker> list) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withMarkers(Marker... markers) {
        throw new NotImplementedException();
    }

    @Override
    public HttpRequest withDefaultHeaders() {
        throw new NotImplementedException();
    }
}
