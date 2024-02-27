/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.Objects;
import java.util.stream.Collectors;

public class LogEntity {
    private final ProxyHttpRequestResponse requestResponse;
    private final RegexEntity regexEntity;
    /**
     * string from the body that matches
     */
    private final String match;

    public LogEntity(ProxyHttpRequestResponse requestResponse, RegexEntity regexEntity, String match) {
        this.requestResponse = requestResponse;
        this.regexEntity = regexEntity;
        this.match = match;
    }

    public ProxyHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public RegexEntity getRegexEntity() {
        return regexEntity;
    }

    public String getMatch() {
        return match;
    }

    /**
     * The equals method is required for the de-duplication of results in the Logger table.
     * When two LogEntity are equal, only one entry is kept in the Logger table.
     * The current implementation consider two LogEntity equals when:
     * - the matched content is the same;
     * - the matched regex is the same;
     * - the request URL is the same;
     * - the response headers are the same. This should cover most of the cases as responses usually contain the Date header;
     *
     * @param o the object to check equality against this
     * @return true if they are the same object instance or if all the conditions defined above are true;
     */
    @Override
    public boolean equals(Object o) {
        //TODO when LogEntity will keep track of matched section, equals should consider different two Entities with different sections matched
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LogEntity logEntity = (LogEntity) o;

        return Objects.equals(
                this.getMatch(),
                logEntity.getMatch()) &&
                Objects.equals(
                        this.getRegexEntity(),
                        logEntity.getRegexEntity()) &&
                Objects.equals(
                        this.getRequestResponse().finalRequest().url(),
                        logEntity.getRequestResponse().finalRequest().url()) &&
                Objects.equals(
                        this.getRequestResponse().response().headers().stream().map(HttpHeader::toString).collect(Collectors.joining("\r\n")),
                        logEntity.getRequestResponse().response().headers().stream().map(HttpHeader::toString).collect(Collectors.joining("\r\n")));
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRequestResponse(), getRegexEntity(), getMatch());
    }

    @Override
    public String toString() {
        return "LogEntity{" +
                "url='" + requestResponse.finalRequest().url() + '\'' +
                ", regex='" + regexEntity.getDescription() + '\'' +
                ", match='" + match + '\'' +
                '}';
    }
}