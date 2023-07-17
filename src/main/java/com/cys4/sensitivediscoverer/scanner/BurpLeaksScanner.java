/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.scanner;

import burp.*;
import com.cys4.sensitivediscoverer.controller.Utils;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.ui.MainUI;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BurpLeaksScanner {

    private final MainUI mainUI;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final List<LogEntity> logEntries;
    private final List<RegexEntity> regexList;
    private final List<RegexEntity> extensionsList;
    private final List<String> blacklistedMimeTypes;
    private final Gson gson;
    private boolean interruptScan;
    private int numThreads;

    // analyzeProxyHistory
    private int analyzedItems = 0;
    private final Object analyzeLock = new Object();

    public BurpLeaksScanner(int numThreads, MainUI mainUI, IBurpExtenderCallbacks callbacks, List<LogEntity> logEntries,
            List<RegexEntity> regexList, List<RegexEntity> extensionsList) {
        this.numThreads = numThreads;
        this.mainUI = mainUI;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.logEntries = logEntries;
        this.regexList = regexList;
        this.extensionsList = extensionsList;
        this.blacklistedMimeTypes = new ArrayList<>();
        this.interruptScan = false;
        this.gson = new Gson();
    }

    /**
     * Method for analyzing the elements in Burp > Proxy > HTTP history
     */
    public void analyzeProxyHistory(JProgressBar progressBar) {
        IHttpRequestResponse[] httpProxyItems = callbacks.getProxyHistory();
        this.analyzedItems = 0;

        progressBar.setMaximum(httpProxyItems.length);
        progressBar.setValue(this.analyzedItems);
        progressBar.setStringPainted(true);

        // create copy of regex list to protect from changes while scanning
        List<RegexEntity> allRegexListCopy = Stream
                .concat(regexList.stream(), extensionsList.stream())
                .map(RegexEntity::new)
                .toList();

        // setup filter parameters for analysis
        boolean inScope = MainUI.isInScopeOptionSelected();
        boolean checkMimeType = MainUI.isSkipMediaTypeOptionSelected();
        int maxRequestSize = MainUI.isSkipMaxSizeOptionSelected() ? this.mainUI.getMaxSizeValueOption() : -1;

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        for (int i = 0; i < httpProxyItems.length; i++) {
            IHttpRequestResponse httpProxyItem = httpProxyItems[i];
            int reqNumber = i+1;
            executor.execute(() -> {
                analyzeSingleMessage(httpProxyItem, reqNumber, allRegexListCopy, inScope, checkMimeType, maxRequestSize);

                if (interruptScan) return;

                synchronized (analyzeLock) {
                    ++this.analyzedItems;
                }
                progressBar.setValue(this.analyzedItems);
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
     */
    private void analyzeSingleMessage(IHttpRequestResponse httpProxyItem, int requestNumber, List<RegexEntity> regexList,
                                      boolean inScopeSelected, boolean checkMimeType, int maxRequestSize) {
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
        if (checkMimeType && isMimeTypeBlacklisted(responseInfo.getStatedMimeType(), responseInfo.getInferredMimeType())) return;

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
                        addLogEntry(
                                httpProxyItem,
                                requestNumber,
                                entry.getDescription(),
                                entry.getRegex(),
                                matcher.group());
                    }
                });
        }
    }

    private List<Matcher> getRegexMatchers(RegexEntity regex, String requestUrl, String requestHeaders, String requestBody, String responseHeaders, String responseBody) {
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

    private void addLogEntry(IHttpRequestResponse httpProxyItem, int requestNumber, String description, String regex, String match) {
        // create a new log entry with the message details
        int row = logEntries.size();

        // the group method is used for retrieving the context in which the regex has matched
        LogEntity logEntry = new LogEntity(
            httpProxyItem,
            requestNumber,
            helpers.analyzeRequest(httpProxyItem).getUrl(),
            description,
            regex,
            match);

        if (!logEntries.contains(logEntry)) {
            logEntries.add(logEntry);
            mainUI.logTableEntriesUIAddNewRow(row);
        }
    }

    /**
     * Checks if the MimeType is inside the list of blacklisted mime types "mime_types.json".
     * If the stated mime type in the header isBlank, then the inferred mime type is used.
     * @param statedMimeType Stated mime type from a IResponseInfo object
     * @param inferredMimeType Inferred mime type from a IResponseInfo object
     * @return True if the mime type is blacklisted
     */
    private boolean isMimeTypeBlacklisted(String statedMimeType, String inferredMimeType) {
        String mimeType = statedMimeType.isBlank() ? inferredMimeType : statedMimeType;

        if (this.blacklistedMimeTypes.isEmpty()) {
            Type tArrayListString = new TypeToken<ArrayList<String>>() {}.getType();
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

    public int getNumThreads() {
        return numThreads;
    }

    public void setNumThreads(int numThreads) {
        this.numThreads = numThreads;
    }
}
