/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import burp.*;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RegexScanner {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final ScannerOptions scannerOptions;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;
    /**
     * List of MIME types to ignore if matched while scanning
     */
    private final List<String> blacklistedMimeTypes;
    private final Gson gson;
    /**
     * Flag that indicates if the scan must be interrupted.
     * Used to interrupt scan before completion.
     */
    private boolean interruptScan;
    public RegexScanner(MainUI mainUI,
                        ScannerOptions scannerOptions,
                        List<RegexEntity> generalRegexList,
                        List<RegexEntity> extensionsRegexList) {
        this.callbacks = mainUI.getCallbacks();
        this.scannerOptions = scannerOptions;
        this.helpers = callbacks.getHelpers();
        this.generalRegexList = generalRegexList;
        this.extensionsRegexList = extensionsRegexList;
        this.blacklistedMimeTypes = new ArrayList<>();
        this.interruptScan = false;
        this.gson = new Gson();
    }

    /**
     * Method for analyzing the elements in Burp > Proxy > HTTP history
     *
     * @param itemAnalyzedCallback A callback that's called after analysing each item with the maxItemsCount as the argument
     * @param logEntriesCallback   A callback that's called for every new finding, with the LogEntity as an argument
     */
    public void analyzeProxyHistory(Consumer<Integer> itemAnalyzedCallback, Consumer<LogEntity> logEntriesCallback) {
        IHttpRequestResponse[] httpProxyItems = callbacks.getProxyHistory();

        // create copy of regex list to protect from changes while scanning
        List<RegexEntity> allRegexListCopy = Stream
                .concat(generalRegexList.stream(), extensionsRegexList.stream())
                .map(RegexEntity::new)
                .toList();

        // setup filter parameters for analysis
        boolean inScope = scannerOptions.isFilterInScopeCheckbox();
        boolean checkMimeType = scannerOptions.isFilterSkipMediaTypeCheckbox();
        int maxRequestSize = scannerOptions.isFilterSkipMaxSizeCheckbox() ? scannerOptions.getConfigMaxResponseSize() : -1;

        ExecutorService executor = Executors.newFixedThreadPool(scannerOptions.getConfigNumberOfThreads());
        for (int i = 0; i < httpProxyItems.length; i++) {
            IHttpRequestResponse httpProxyItem = httpProxyItems[i];
            int reqNumber = i + 1;
            executor.execute(() -> {
                //todo pass options as single object
                analyzeSingleMessage(httpProxyItem, reqNumber, allRegexListCopy, logEntriesCallback, inScope, checkMimeType, maxRequestSize);

                if (interruptScan) return;

                //todo send maxLength only first time
                itemAnalyzedCallback.accept(httpProxyItems.length);
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
     * @param httpProxyItem
     * @param requestNumber
     * @param regexList
     * @param logEntriesCallback
     * @param inScopeSelected
     * @param checkMimeType
     * @param maxRequestSize
     */
    private void analyzeSingleMessage(IHttpRequestResponse httpProxyItem,
                                      int requestNumber,
                                      List<RegexEntity> regexList,
                                      Consumer<LogEntity> logEntriesCallback, boolean inScopeSelected,
                                      boolean checkMimeType,
                                      int maxRequestSize) {
        // check if URL is in scope
        byte[] request = httpProxyItem.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(httpProxyItem);
        if (inScopeSelected && (!callbacks.isInScope(requestInfo.getUrl()))) return;

        // skip empty responses
        byte[] response = httpProxyItem.getResponse();
        if (Objects.isNull(response)) return;
        // check for max request size
        if (maxRequestSize > 0 && response.length > maxRequestSize) return;

        // check for blacklisted MIME types
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        if (checkMimeType && isMimeTypeBlacklisted(responseInfo.getStatedMimeType(), responseInfo.getInferredMimeType()))
            return;

        int requestBodyOffset = requestInfo.getBodyOffset();
        String requestBody = helpers.bytesToString(Arrays.copyOfRange(request, requestBodyOffset, request.length));
        String requestHeaders = String.join("\r\n", requestInfo.getHeaders());

        int responseBodyOffset = responseInfo.getBodyOffset();
        String responseBody = helpers.bytesToString(Arrays.copyOfRange(response, responseBodyOffset, response.length));
        String responseHeaders = String.join("\r\n", responseInfo.getHeaders());

        String requestUrl = requestInfo.getUrl().toString();

        for (RegexEntity entry : regexList) {
            if (this.interruptScan) return;

            // if the box related to the regex in the Options tab of the extension is checked
            if (!entry.isActive()) continue;

            getRegexMatchers(entry, requestUrl, requestHeaders, requestBody, responseHeaders, responseBody)
                    .parallelStream()
                    .forEach(matcher -> {
                        while (matcher.find()) {
                            logEntriesCallback.accept(new LogEntity(
                                    httpProxyItem,
                                    requestNumber,
                                    helpers.analyzeRequest(httpProxyItem).getUrl(),
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
     * @param statedMimeType   Stated mime type from a IResponseInfo object
     * @param inferredMimeType Inferred mime type from a IResponseInfo object
     * @return True if the mime type is blacklisted
     */
    private boolean isMimeTypeBlacklisted(String statedMimeType, String inferredMimeType) {
        String mimeType = statedMimeType.isBlank() ? inferredMimeType : statedMimeType;

        if (this.blacklistedMimeTypes.isEmpty()) {
            Type tArrayListString = new TypeToken<ArrayList<String>>() {
            }.getType();
            Stream.of("mime_types.json")
                    .map(Utils::readResourceFile)
                    .<List<String>>map(mimeTypes -> gson.fromJson(mimeTypes, tArrayListString))
                    // if res == null, then blacklisted will remain empty, which is fine
                    .filter(Objects::nonNull)
                    .flatMap(Collection::stream)
                    .forEach(blacklistedMimeTypes::add);
        }

        return blacklistedMimeTypes.contains(mimeType.toUpperCase());
    }

    public void setInterruptScan(boolean interruptScan) {
        this.interruptScan = interruptScan;
    }
}
