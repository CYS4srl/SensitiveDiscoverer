package com.cys4.sensitivediscoverer;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.cys4.sensitivediscoverer.model.ScannerOptions;

import java.util.Objects;

public class UtilsScanner {
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
}
