/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RegexScanner {
    private final MontoyaApi burpApi;
    private final ScannerOptions scannerOptions;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;
    /**
     * Flag that indicates if the scan must be interrupted.
     * Used to interrupt scan before completion.
     */
    private boolean interruptScan;
    /**
     * List of MIME types to ignore while scanning when the relevant option is enabled
     */
    private final EnumSet<MimeType> blacklistedMimeTypes = EnumSet.of(
            MimeType.APPLICATION_FLASH,
            MimeType.FONT_WOFF,
            MimeType.FONT_WOFF2,
            MimeType.IMAGE_BMP,
            MimeType.IMAGE_GIF,
            MimeType.IMAGE_JPEG,
            MimeType.IMAGE_PNG,
            MimeType.IMAGE_SVG_XML,
            MimeType.IMAGE_TIFF,
            MimeType.IMAGE_UNKNOWN,
            MimeType.LEGACY_SER_AMF,
            MimeType.RTF,
            MimeType.SOUND,
            MimeType.VIDEO
    );;

    public RegexScanner(MontoyaApi burpApi,
                        ScannerOptions scannerOptions,
                        List<RegexEntity> generalRegexList,
                        List<RegexEntity> extensionsRegexList) {
        this.burpApi = burpApi;
        this.scannerOptions = scannerOptions;
        this.generalRegexList = generalRegexList;
        this.extensionsRegexList = extensionsRegexList;
        this.interruptScan = false;
    }

    /**
     * Method for analyzing the elements in Burp > Proxy > HTTP history
     *
     * @param itemAnalyzedCallback A callback that's called after analysing each item with the maxItemsCount as the argument
     * @param logEntriesCallback   A callback that's called for every new finding, with the LogEntity as an argument
     */
    public void analyzeProxyHistory(Consumer<Integer> itemAnalyzedCallback, Consumer<LogEntity> logEntriesCallback) {
        List<ProxyHttpRequestResponse> proxyEntries = this.burpApi.proxy().history();

        // create copy of regex list to protect from changes while scanning
        List<RegexEntity> allRegexListCopy = Stream
                .concat(generalRegexList.stream(), extensionsRegexList.stream())
                .map(RegexEntity::new)
                .toList();

        ExecutorService executor = Executors.newFixedThreadPool(scannerOptions.getConfigNumberOfThreads());
        proxyEntries.forEach(proxyEntry -> {
            executor.execute(() -> {
                analyzeSingleMessage(allRegexListCopy, scannerOptions, proxyEntry, logEntriesCallback);

                if (interruptScan) return;

                itemAnalyzedCallback.accept(proxyEntries.size());
            });
        });

        try {
            executor.shutdown();
            while (!executor.isTerminated()) {
                if (this.interruptScan)
                    executor.shutdownNow();

                Thread.sleep(200);
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    /**
     * The main method that scan for regex in the single request body
     *
     * @param regexList          list of regexes to try and match
     * @param scannerOptions     options for the scanner
     * @param proxyEntry         the item (request/response) from burp's http proxy
     * @param logEntriesCallback A callback function where to report findings
     */
    private void analyzeSingleMessage(List<RegexEntity> regexList,
                                      ScannerOptions scannerOptions,
                                      ProxyHttpRequestResponse proxyEntry,
                                      Consumer<LogEntity> logEntriesCallback) {
        // check if URL is in scope
        HttpRequest request = proxyEntry.finalRequest();
        if (scannerOptions.isFilterInScopeCheckbox() && (!request.isInScope())) return;

        // skip empty responses
        HttpResponse response = proxyEntry.response();
        if (Objects.isNull(response)) return;
        // check for max request size
        if (scannerOptions.isFilterSkipMaxSizeCheckbox() && response.body().length() > scannerOptions.getConfigMaxResponseSize())
            return;

        // check for blacklisted MIME types
        if (scannerOptions.isFilterSkipMediaTypeCheckbox() && isMimeTypeBlacklisted(response.statedMimeType(), response.inferredMimeType()))
            return;

        String requestBody = request.bodyToString();
        String requestHeaders = String.join("\r\n", request.headers().stream().map(HttpHeader::toString).toList());

        String responseBody = response.bodyToString();
        String responseHeaders = String.join("\r\n", response.headers().stream().map(HttpHeader::toString).toList());

        for (RegexEntity entry : regexList) {
            if (this.interruptScan) return;

            // if the box related to the regex in the Options tab of the extension is checked
            if (!entry.isActive()) continue;

            getRegexMatchers(entry, request.url(), requestHeaders, requestBody, responseHeaders, responseBody)
                    .parallelStream()
                    .forEach(matcher -> {
                        while (matcher.find()) {
                            logEntriesCallback.accept(new LogEntity(
                                    proxyEntry,
                                    entry,
                                    matcher.group()));
                        }
                    });
        }
    }

    private List<Matcher> getRegexMatchers(RegexEntity regex,
                                           String requestUrl,
                                           String requestHeaders,
                                           String requestBody,
                                           String responseHeaders,
                                           String responseBody) {
        Pattern regexCompiled = regex.getRegexCompiled();

        //TODO keep track of section where regex matched. Show the section in the logger table;
        return regex.getSections()
                .parallelStream()
                .map(proxyItemSection -> switch (proxyItemSection) {
                    case REQ_URL -> requestUrl;
                    case REQ_HEADERS -> requestHeaders;
                    case REQ_BODY -> requestBody;
                    case RES_HEADERS -> responseHeaders;
                    case RES_BODY -> responseBody;
                })
                .filter(Objects::nonNull)
                .map(regexCompiled::matcher)
                .collect(Collectors.toList());
    }

    /**
     * Checks if the MimeType is inside the list of blacklisted mime types "mime_types.json".
     * If the stated mime type in the header isBlank, then the inferred mime type is used.
     *
     * @param statedMimeType   Stated mime type from a HttpResponse object
     * @param inferredMimeType Inferred mime type from a HttpResponse object
     * @return True if the mime type is blacklisted
     */
    private boolean isMimeTypeBlacklisted(MimeType statedMimeType, MimeType inferredMimeType) {
        return blacklistedMimeTypes.contains(Objects.isNull(statedMimeType) ? inferredMimeType : statedMimeType);
    }

    /**
     * Change the interrupt flag that dictates whether to stop the current scan
     *
     * @param interruptScan flag value. If true, scan gets interrupted as soon as possible.
     */
    public void setInterruptScan(boolean interruptScan) {
        this.interruptScan = interruptScan;
    }
}
