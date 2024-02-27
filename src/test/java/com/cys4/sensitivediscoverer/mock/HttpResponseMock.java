package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;
import org.apache.commons.lang3.NotImplementedException;

import java.util.List;
import java.util.regex.Pattern;

public class HttpResponseMock implements HttpResponse {
    private final String body;
    private final List<HttpHeader> headers;

    public HttpResponseMock(String body, List<HttpHeader> headers) {
        this.body = body;
        this.headers = headers;
    }

    public HttpResponseMock(String body) {
        this(body, List.of(new HttpHeaderMock("Host", "test.com")));
    }

    @Override
    public String bodyToString() {
        return this.body;
    }

    @Override
    public List<HttpHeader> headers() {
        return this.headers;
    }

    @Override
    public short statusCode() {
        throw new NotImplementedException();
    }

    @Override
    public String reasonPhrase() {
        throw new NotImplementedException();
    }

    @Override
    public boolean isStatusCodeClass(StatusCodeClass statusCodeClass) {
        throw new NotImplementedException();
    }

    @Override
    public List<Cookie> cookies() {
        throw new NotImplementedException();
    }

    @Override
    public Cookie cookie(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String cookieValue(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasCookie(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean hasCookie(Cookie cookie) {
        throw new NotImplementedException();
    }

    @Override
    public MimeType mimeType() {
        throw new NotImplementedException();
    }

    @Override
    public MimeType statedMimeType() {
        throw new NotImplementedException();
    }

    @Override
    public MimeType inferredMimeType() {
        throw new NotImplementedException();
    }

    @Override
    public List<KeywordCount> keywordCounts(String... strings) {
        throw new NotImplementedException();
    }

    @Override
    public List<Attribute> attributes(AttributeType... attributeTypes) {
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
    public HttpResponse copyToTempFile() {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withStatusCode(short i) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withReasonPhrase(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withHttpVersion(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withBody(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withBody(ByteArray byteArray) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withAddedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withAddedHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withUpdatedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withUpdatedHeader(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withRemovedHeader(HttpHeader httpHeader) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withRemovedHeader(String s) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withMarkers(List<Marker> list) {
        throw new NotImplementedException();
    }

    @Override
    public HttpResponse withMarkers(Marker... markers) {
        throw new NotImplementedException();
    }
}
