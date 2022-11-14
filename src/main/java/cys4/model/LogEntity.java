/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import burp.IHttpRequestResponse;

import java.net.URL;
import java.util.concurrent.atomic.AtomicInteger;

public class LogEntity {
    private int idRequest;
    private final static AtomicInteger counter = new AtomicInteger(0);
    private final IHttpRequestResponse requestResponse;
    private final URL url;
    private final String regex;
    private final String match; // string from the body that matches
    private final String host;
    private final int port;
    private final String protocol;
    private final boolean isSSL;

    public LogEntity(IHttpRequestResponse requestResponse, URL url, String regex, String match) {
        this.idRequest = getCounterIdRequest();

        incrementCounter();

        this.requestResponse = requestResponse;
        this.url = url;
        this.regex = regex;
        this.match = match;
        this.host = requestResponse.getHttpService().getHost();
        this.protocol = requestResponse.getHttpService().getProtocol();
        this.port = requestResponse.getHttpService().getPort();
        this.isSSL = this.protocol.equals("https");
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

    public String getProtocol() {
        return protocol;
    }

    public boolean isSSL() {
        return isSSL;
    }

    // return the current value of our counter
    public static int getCounterIdRequest() {
        return counter.get();
    }

    // increment the counter in thread safe mode
    private static void incrementCounter() {
        while (true) {
            int existingValue = getCounterIdRequest();
            int newValue = existingValue + 1;
            if (counter.compareAndSet(existingValue, newValue)) {
                return;
            }
        }
    }

    // reset the counter
    public static void setIdRequest(int counterParam) {
        int existingValue = getCounterIdRequest();
        if (existingValue != counterParam) {
            while (true) {
                if (counter.compareAndSet(existingValue, counterParam)) {
                    return;
                }
            }
        }
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
}