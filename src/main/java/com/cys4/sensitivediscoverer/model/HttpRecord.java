package com.cys4.sensitivediscoverer.model;

/**
 * Record containing the various section of an HTTP request/response object
 *
 * @param requestUrl
 * @param requestHeaders
 * @param requestBody
 * @param responseHeaders
 * @param responseBody
 */
public record HttpRecord(
        String requestUrl,
        String requestHeaders,
        String requestBody,
        String responseHeaders,
        String responseBody
) {
}