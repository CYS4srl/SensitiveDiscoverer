package com.cys4.sensitivediscoverer.model;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A LogEntity represents the results of a successful match of a regex in a request/response.
 * <p>
 * <b>Note</b>:<br>
 * LogEntity instance that reference a specific row in a table are usually named logEntry.
 * </p>
 * <p>
 * <b>Dev notes</b>:<br>
 * This entity contains immutable references to:
 * <ul>
 *  <li>the request object</li>
 *  <li>the response object</li>
 *  <li>the url of the request</li>
 *  <li>the matched regex</li>
 *  <li>the section where the regex matched</li>
 *  <li>the results of the match</li>
 * </ul>
 * Some information, such as the URL, could be considered redundant but serves as a cache layer between the extension and the Burp APIs.
 * Calling request.url() is slow, therefore a copy is kept here as the underlying request is not going to change.
 */
public class LogEntity {
    private final HttpRequest request;
    private final HttpResponse response;
    private final RegexEntity regexEntity;
    /**
     * Section where the regex matched.
     */
    private final HttpSection matchedSection;
    /**
     * String matched with the regex on 1+ sections (specific sections not currently tracked).
     */
    private final String match;
    /**
     * Cached value from request.url()
     */
    private String requestUrl;
    /**
     * Cached value from the response field
     */
    private String responseHeaders;

    public LogEntity(HttpRequest request, HttpResponse httpResponse, RegexEntity regexEntity, HttpSection matchedSection, String match) {
        this.request = request;
        this.response = httpResponse;
        this.regexEntity = regexEntity;
        this.matchedSection = matchedSection;
        this.match = match;
        this.requestUrl = null;
        this.responseHeaders = null;
    }

    public RegexEntity getRegexEntity() {
        return regexEntity;
    }

    public HttpSection getMatchedSection() {
        return matchedSection;
    }

    public String getMatch() {
        return match;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    /**
     * The URL from the request.
     * Cached version of request.url()
     */
    public String getRequestUrl() {
        if (this.requestUrl == null) {
            this.requestUrl = this.request.url();
        }
        return this.requestUrl;
    }

    /**
     * The Headers of the response as a String with single headers separated by the usual CRLF.
     * Cached version from response.headers()
     */
    private String getResponseHeaders() {
        if (this.responseHeaders == null) {
            this.responseHeaders = this.response.headers().stream().map(HttpHeader::toString).collect(Collectors.joining("\r\n"));
        }
        return this.responseHeaders;
    }

    /**
     * The equals method is required for the de-duplication of results in the Logger table.
     * When two LogEntity are equal, only one entry is kept in the Logger table.
     * The current implementation consider two LogEntity equals when:
     * - the matched content is the same;
     * - the section of the match is the same;
     * - the matched regex is the same;
     * - the request URL is the same;
     * - the response headers are the same. This should cover most of the cases as responses usually contain the Date header;
     *
     * @param o the object to check equality against this
     * @return true if they are the same object instance or if all the conditions defined above are true;
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LogEntity logEntity = (LogEntity) o;

        return Objects.equals(
                this.getMatch(),
                logEntity.getMatch()) &&
                this.getMatchedSection() == logEntity.getMatchedSection() &&
                Objects.equals(
                        this.getRegexEntity(),
                        logEntity.getRegexEntity()) &&
                Objects.equals(
                        this.getRequestUrl(),
                        logEntity.getRequestUrl()) &&
                Objects.equals(
                        this.getResponseHeaders(),
                        logEntity.getResponseHeaders());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRequest(), getResponse(), getRegexEntity(), getMatchedSection(), getMatch());
    }

    @Override
    public String toString() {
        return "LogEntity{" +
                "url='" + getRequestUrl() + '\'' +
                ", regex='" + regexEntity.getDescription() + '\'' +
                ", section='" + getMatchedSection() + '\'' +
                ", match='" + getMatch() + '\'' +
                '}';
    }
}
