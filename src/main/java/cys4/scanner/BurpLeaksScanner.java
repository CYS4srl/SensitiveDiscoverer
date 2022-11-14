/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cys4.controller.Utils;
import cys4.model.ExtensionEntity;
import cys4.model.LogEntity;
import cys4.model.RegexEntity;
import cys4.ui.MainUI;

import java.lang.reflect.Type;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;

import javax.swing.JProgressBar;

public class BurpLeaksScanner {

    private MainUI mainUI;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private List<LogEntity> logEntries = new ArrayList<>();
    private List<RegexEntity> regexList = new ArrayList<>();
    private List<ExtensionEntity> extensionList = new ArrayList<>();
    private ArrayList<String> l_blacklistedMimeTypes;
    private Gson _gson;
    public boolean interruptScan;

    // analyzeProxyHistory
    private int analyzedItems = 0;
    private Object analyzeLock = new Object();

    public BurpLeaksScanner(MainUI mainUI, IBurpExtenderCallbacks callbacks, List<LogEntity> logEntries,
            List<RegexEntity> regexList, List<ExtensionEntity> extensionList) {
        this.mainUI = mainUI;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.logEntries = logEntries;
        this.regexList = regexList;
        this.extensionList = extensionList;
        this.interruptScan = false;

        for (RegexEntity entry : regexList) {
            entry.compileRegex();
        }

        for (ExtensionEntity entry : extensionList) {
            entry.compileRegex();
        }
    }

    /**
     * Method for analyzing the elements in Burp > Proxy > HTTP history
     * @param progressBar
     */
    public void analyzeProxyHistory(JProgressBar progressBar) {
        IHttpRequestResponse[] httpRequests;
        httpRequests = callbacks.getProxyHistory();

        progressBar.setMaximum(httpRequests.length);
        this.analyzedItems = 0;
        progressBar.setValue(this.analyzedItems);
        progressBar.setStringPainted(true);

        LogEntity.setIdRequest(0); // responseId will start at 0

        ExecutorService executor = Executors.newFixedThreadPool(5);

        for (IHttpRequestResponse httpProxyItem : httpRequests) {
            executor.execute(() -> {
                analyzeSingleMessage(httpProxyItem);
                synchronized (analyzeLock) {
                    this.analyzedItems++;
                }
                progressBar.setValue(this.analyzedItems);
            });

        }

        try {
            executor.shutdown();
            while (!executor.isTerminated()) {
                if (this.interruptScan)
                    executor.shutdownNow();

                Thread.sleep(500);
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    /**
     * The main method that scan for regex in the single request body
     * @param httpProxyItem
     */
    private void analyzeSingleMessage(IHttpRequestResponse httpProxyItem) {
        URL requestURL = helpers.analyzeRequest(httpProxyItem).getUrl();

        if (Objects.isNull(httpProxyItem.getResponse())) return;
        if (MainUI.isInScopeSelected() && (!callbacks.isInScope(requestURL))) return;

        IResponseInfo response = helpers.analyzeResponse(httpProxyItem.getResponse());
        if (!isValidMimeType(response.getStatedMimeType(), response.getInferredMimeType())) return;

        // convert from bytes to string the body of the request
        String responseBody = helpers.bytesToString(httpProxyItem.getResponse());
        for (RegexEntity entry : regexList) {

            // if the box related to the regex in the Options tab of the extension is checked
            if (entry != null && entry.isActive()) {
                Matcher regex_matcher = entry.getRegexCompiled().matcher(responseBody);

                while (regex_matcher.find()) {
                    // create a new log entry with the message details
                    addLogEntry(
                        httpProxyItem,
                        entry.getDescription() + " - " + entry.getRegex(),
                        regex_matcher.group());
                }

            }
        }

        for (ExtensionEntity entry : extensionList) {
            if (entry.isActive()) {
                String extension = entry.getExtension();

                Matcher extension_matcher = entry.getRegexCompiled().matcher(requestURL.toString());
                // add the new entry if do not exist
                if (extension_matcher.find()) {
                    addLogEntry(
                        httpProxyItem,
                        "EXT " + entry.getDescription() + " - " + extension,
                        extension);
                }
            }
        }
    }

    private void addLogEntry(IHttpRequestResponse httpProxyItem, String description, String match) {
        // create a new log entry with the message details
        int row = logEntries.size();

        // the group method is used for retrieving the context in which the regex has matched
        LogEntity logEntry = new LogEntity(
            httpProxyItem,
            helpers.analyzeRequest(httpProxyItem).getUrl(),
            description,
            match);

        if (!logEntries.contains(logEntry)) {
            logEntries.add(logEntry);
            mainUI.logTableEntriesUIAddNewRow(row);
        }
    }

    /**
     * Checks if the MimeType is inside the list of valid mime types "mime_types.json".
     * If the stated mime type in the header isBlank, then the inferred mime type is used.
     * @param statedMimeType Stated mime type from a IResponseInfo object
     * @param inferredMimeType Inferred mime type from a IResponseInfo object
     * @return True if the mime type is valid
     */
    private boolean isValidMimeType(String statedMimeType, String inferredMimeType) {
        String mimeType = statedMimeType.isBlank() ? inferredMimeType : statedMimeType;

        if (null == l_blacklistedMimeTypes) {
            l_blacklistedMimeTypes = new ArrayList<>();
            if (null == _gson) {
                _gson = new Gson();
            }

            Type tArrayListString = new TypeToken<ArrayList<String>>() {}.getType();
            List<String> lDeserializedJson = _gson.fromJson(
                Utils.readResourceFile("mime_types.json"),
                tArrayListString);
            for (String element : lDeserializedJson)
                l_blacklistedMimeTypes.add(element);
        }

        return !l_blacklistedMimeTypes.contains(mimeType.toUpperCase());
    }
}
