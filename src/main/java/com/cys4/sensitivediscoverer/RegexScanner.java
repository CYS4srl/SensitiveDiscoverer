/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import com.cys4.sensitivediscoverer.utils.BurpUtils;
import com.cys4.sensitivediscoverer.utils.ScannerUtils;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class RegexScanner {
    /**
     * List of MIME types to ignore while scanning when the relevant option is enabled
     */
    public static final EnumSet<MimeType> blacklistedMimeTypes = EnumSet.of(
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
    );
    private final MontoyaApi burpApi;
    private final ScannerOptions scannerOptions;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;
    /**
     * Flag that indicates if the scan must be interrupted.
     * Used to interrupt scan before completion.
     */
    private boolean interruptScan;

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
     * @param progressBarCallbackSetup A setup function that given the number of items to analyze, returns a Runnable to be called after analysing each item.
     * @param logEntriesCallback       A callback that's called for every new finding, with a LogEntity as the only argument
     */
    public void analyzeProxyHistory(Function<Integer, Runnable> progressBarCallbackSetup, Consumer<LogEntity> logEntriesCallback) {
        // create a copy of the regex list to protect from changes while scanning
        List<RegexEntity> allRegexListCopy = Stream
                .concat(generalRegexList.stream(), extensionsRegexList.stream())
                .map(RegexEntity::new)
                .toList();

        ExecutorService executor = Executors.newFixedThreadPool(scannerOptions.getConfigNumberOfThreads());

        // removing items from the list allows the GC to clean up just after the task is executed
        // instead of waiting until the whole analysis finishes.
        List<ProxyHttpRequestResponse> proxyEntries = this.burpApi.proxy().history();
        Runnable itemAnalyzedCallback = progressBarCallbackSetup.apply(proxyEntries.size());
        for (int entryIndex = proxyEntries.size() - 1; entryIndex >= 0; entryIndex--) {
            ProxyHttpRequestResponse proxyEntry = proxyEntries.remove(entryIndex);
            executor.execute(() -> {
                if (interruptScan) return;
                analyzeSingleMessage(allRegexListCopy, scannerOptions, proxyEntry, logEntriesCallback);
                itemAnalyzedCallback.run();
            });
        }

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
     * @param logEntriesCallback A callback that's called for every new finding, with a LogEntity as the only argument.
     */
    private void analyzeSingleMessage(List<RegexEntity> regexList,
                                      ScannerOptions scannerOptions,
                                      ProxyHttpRequestResponse proxyEntry,
                                      Consumer<LogEntity> logEntriesCallback) {
        // The initial checks must be kept ordered based on the amount of information required from Burp APIs.
        // API calls (to MontoyaAPI) for specific parts of the request/response are quite slow.
        HttpRequest request = proxyEntry.finalRequest();
        if (ScannerUtils.isUrlOutOfScope(scannerOptions, request)) return;
        HttpResponse response = proxyEntry.response();
        if (ScannerUtils.isResponseEmpty(response)) return;
        if (ScannerUtils.isMimeTypeBlacklisted(scannerOptions, response)) return;
        ByteArray responseBody = response.body();
        if (ScannerUtils.isResponseSizeOverMaxSize(scannerOptions, responseBody)) return;

        // Not using bodyToString() as it's extremely slow
        String requestBodyDecoded = BurpUtils.convertByteArrayToString(request.body());
        String requestHeaders = BurpUtils.convertHttpHeaderListToString(request.headers());
        String responseBodyDecoded = BurpUtils.convertByteArrayToString(responseBody);
        String responseHeaders = BurpUtils.convertHttpHeaderListToString(response.headers());

        for (RegexEntity regex : regexList) {
            if (this.interruptScan) return;
            if (!regex.isActive()) continue;

            Consumer<String> logMatchCallback = match -> logEntriesCallback.accept(new LogEntity(request, response, regex, match));
            performMatchingOnMessage(regex, request, requestHeaders, requestBodyDecoded, responseHeaders, responseBodyDecoded, logMatchCallback);
        }
    }

    private void performMatchingOnMessage(RegexEntity regex, HttpRequest request, String requestHeaders, String requestBodyDecoded, String responseHeaders, String responseBodyDecoded, Consumer<String> logMatchCallback) {
        getRegexMatchers(regex, request.url(), requestHeaders, requestBodyDecoded, responseHeaders, responseBodyDecoded)
                .flatMap(Matcher::results)
                .map(MatchResult::group)
                .forEachOrdered(logMatchCallback);
    }

    private Stream<Matcher> getRegexMatchers(RegexEntity regex,
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
                .map(regexCompiled::matcher);
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
