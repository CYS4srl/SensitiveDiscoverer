/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import burp.IHttpRequestResponse;

import java.net.URL;

public class LogEntity {
    private final int idRequest;
    private final IHttpRequestResponse requestResponse;
    private final URL url;
    private final String regex;
    private final String match; // string from the body that matches
    private final String host;
    private final int port;
    private final boolean isSSL;
    private final String description;

    public LogEntity(IHttpRequestResponse requestResponse, int requestNumber, URL url, String description, String regex, String match) {
        this.idRequest = requestNumber;
        this.requestResponse = requestResponse;
        this.url = url;
        this.description = description;
        this.regex = regex;
        this.match = match;
        this.host = requestResponse.getHttpService().getHost();
        String protocol = requestResponse.getHttpService().getProtocol();
        this.port = requestResponse.getHttpService().getPort();
        this.isSSL = protocol.equals("https");
    }

    public int getIdRequest() {
        return this.idRequest;
    }

    public URL getURL() {
        return this.url;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getRegex() {
        return regex;
    }

    public String getMatch() {
        return match;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public boolean isSSL() {
        return isSSL;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof LogEntity)) {
            return false;
        }

        String firstUrl;
        String secondUrl;

        // avoiding useless entry of the same matches on the same site by confronting the non-query part of urls
        if (this.url.getQuery() != null) {
            firstUrl = this.url.toString().replace(this.url.getQuery(), "");
        } else {
            firstUrl = this.url.toString();
        }
        if (((LogEntity) o).url.getQuery() != null) {
            secondUrl = ((LogEntity) o).url.toString().replace(((LogEntity) o).url.getQuery(), "");
        } else {
            secondUrl = ((LogEntity) o).url.toString();
        }

        return (((LogEntity) o).regex.equals(this.regex)) &&
                firstUrl.equals(secondUrl) &&
                ((LogEntity) o).match.equals(this.match);
    }

    public String getDescription() {
        return this.description;
    }
}