package com.cys4.sensitivediscoverer.utils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class BurpUtils {
    public static String convertByteArrayToString(ByteArray request) {
        return new String(request.getBytes(), StandardCharsets.UTF_8);
    }

    public static String convertHttpHeaderListToString(List<HttpHeader> headers) {
        return String.join("\r\n", headers.stream().map(HttpHeader::toString).toList());
    }
}
