package com.cys4.sensitivediscoverer.utils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.cys4.sensitivediscoverer.RegexScanner;
import com.cys4.sensitivediscoverer.model.HttpRecord;
import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.ScannerOptions;

import java.util.Objects;

public class ScannerUtils {
    public static boolean isResponseSizeOverMaxSize(ScannerOptions scannerOptions, ByteArray responseBody) {
        return scannerOptions.isFilterSkipMaxSizeCheckbox() && responseBody.length() > scannerOptions.getConfigMaxResponseSize();
    }

    public static boolean isResponseEmpty(HttpResponse response) {
        return Objects.isNull(response);
    }

    public static boolean isUrlOutOfScope(ScannerOptions scannerOptions, HttpRequest request) {
        return scannerOptions.isFilterInScopeCheckbox() && (!request.isInScope());
    }

    public static boolean isMimeTypeBlacklisted(ScannerOptions scannerOptions, HttpResponse response) {
        return scannerOptions.isFilterSkipMediaTypeCheckbox() && isMimeTypeBlacklisted(response.statedMimeType(), response.inferredMimeType());
    }

    /**
     * Checks if the MimeType is inside the list of blacklisted mime types "mime_types.json".
     * If the stated mime type in the header isBlank, then the inferred mime type is used.
     *
     * @param statedMimeType   Stated mime type from a HttpResponse object
     * @param inferredMimeType Inferred mime type from a HttpResponse object
     * @return True if the mime type is blacklisted
     */
    public static boolean isMimeTypeBlacklisted(MimeType statedMimeType, MimeType inferredMimeType) {
        return RegexScanner.blacklistedMimeTypes.contains(Objects.isNull(statedMimeType) ? inferredMimeType : statedMimeType);
    }

    public static SectionTextRecord getSectionText(HttpSection httpSection, HttpRecord httpRecord) {
        return switch (httpSection) {
            case REQ_URL -> new SectionTextRecord(HttpSection.REQ_URL, httpRecord.requestUrl());
            case REQ_HEADERS -> new SectionTextRecord(HttpSection.REQ_HEADERS, httpRecord.requestHeaders());
            case REQ_BODY -> new SectionTextRecord(HttpSection.REQ_BODY, httpRecord.requestBody());
            case RES_HEADERS -> new SectionTextRecord(HttpSection.RES_HEADERS, httpRecord.responseHeaders());
            case RES_BODY -> new SectionTextRecord(HttpSection.RES_BODY, httpRecord.responseBody());
        };
    }

    public record SectionTextRecord(HttpSection section, String text) {
    }
}
