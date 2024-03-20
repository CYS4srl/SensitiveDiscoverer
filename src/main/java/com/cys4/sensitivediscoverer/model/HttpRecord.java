package com.cys4.sensitivediscoverer.model;

public record HttpRecord(
        String requestUrl,
        String requestHeaders,
        String requestBody,
        String responseHeaders,
        String responseBody
) {
}