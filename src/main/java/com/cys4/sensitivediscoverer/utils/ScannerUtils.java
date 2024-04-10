package com.cys4.sensitivediscoverer.utils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.cys4.sensitivediscoverer.RegexScanner;
import com.cys4.sensitivediscoverer.model.HttpRecord;
import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.RegexScannerOptions;

import java.util.Objects;

public class ScannerUtils {
    public static boolean isResponseSizeOverMaxSize(RegexScannerOptions scannerOptions, ByteArray responseBody) {
        return scannerOptions.isFilterSkipMaxSizeCheckbox() && responseBody.length() > scannerOptions.getConfigMaxResponseSize();
    }

    public static boolean isResponseEmpty(HttpResponse response) {
        return Objects.isNull(response);
    }

    public static boolean isUrlOutOfScope(RegexScannerOptions scannerOptions, HttpRequest request) {
        return scannerOptions.isFilterInScopeCheckbox() && (!request.isInScope());
    }

    public static boolean isMimeTypeBlacklisted(RegexScannerOptions scannerOptions, HttpResponse response) {
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

    /**
     * Returns the specified section of an HTTP record
     *
     * @param httpRecord  The record to use for the selection
     * @param httpSection The section to get from the record
     * @return A record containing both the section and the content of the section
     */
    public static HttpSectionContentRecord getHttpRecordSection(HttpRecord httpRecord, HttpSection httpSection) {
        return switch (httpSection) {
            case REQ_URL -> new HttpSectionContentRecord(HttpSection.REQ_URL, httpRecord.requestUrl());
            case REQ_HEADERS -> new HttpSectionContentRecord(HttpSection.REQ_HEADERS, httpRecord.requestHeaders());
            case REQ_BODY -> new HttpSectionContentRecord(HttpSection.REQ_BODY, httpRecord.requestBody());
            case RES_HEADERS -> new HttpSectionContentRecord(HttpSection.RES_HEADERS, httpRecord.responseHeaders());
            case RES_BODY -> new HttpSectionContentRecord(HttpSection.RES_BODY, httpRecord.responseBody());
        };
    }

    /**
     * Record of a specific section's content of an HTTP entry
     *
     * @param section The content's section inside an HTTP entry
     * @param content The content associated with the specified section
     */
    public record HttpSectionContentRecord(HttpSection section, String content) {
    }
}
