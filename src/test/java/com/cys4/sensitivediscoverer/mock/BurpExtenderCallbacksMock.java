package com.cys4.sensitivediscoverer.mock;

import burp.*;
import org.apache.commons.lang3.NotImplementedException;

import java.awt.*;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

public class BurpExtenderCallbacksMock implements IBurpExtenderCallbacks {
    private IExtensionHelpers extensionHelpers;
    private IHttpRequestResponse[] proxyHistory;
    private Predicate<URL> isInScopePredicate;

    @Override
    public IExtensionHelpers getHelpers() {
        return extensionHelpers;
    }

    public void setHelpers(IExtensionHelpers extensionHelpers) {
        this.extensionHelpers = extensionHelpers;
    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return proxyHistory;
    }

    public void setProxyHistory(IHttpRequestResponse[] proxyHistory) {
        this.proxyHistory = proxyHistory;
    }

    @Override
    public boolean isInScope(URL url) {
        return isInScopePredicate.test(url);
    }

    public void setIsInScopePredicate(Predicate<URL> isInScopePredicate) {
        this.isInScopePredicate = isInScopePredicate;
    }

    @Override
    public void addSuiteTab(ITab tab) {
        if (Objects.isNull(tab)) throw new IllegalArgumentException("Tab is null");
    }

    @Override
    public void customizeUiComponent(Component component) {
    }

    @Override
    public OutputStream getStdout() {
        return System.out;
    }

    @Override
    public OutputStream getStderr() {
        return System.err;
    }

    @Override
    public ITextEditor createTextEditor() {
        return new TextEditorMock();
    }

    @Override
    public void setExtensionName(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void printOutput(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void printError(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener iExtensionStateListener) {
        throw new NotImplementedException();
    }

    @Override
    public List<IExtensionStateListener> getExtensionStateListeners() {
        throw new NotImplementedException();
    }

    @Override
    public void removeExtensionStateListener(IExtensionStateListener iExtensionStateListener) {
        throw new NotImplementedException();
    }

    @Override
    public void registerHttpListener(IHttpListener iHttpListener) {
        throw new NotImplementedException();
    }

    @Override
    public List<IHttpListener> getHttpListeners() {
        throw new NotImplementedException();
    }

    @Override
    public void removeHttpListener(IHttpListener iHttpListener) {
        throw new NotImplementedException();
    }

    @Override
    public void registerProxyListener(IProxyListener iProxyListener) {
        throw new NotImplementedException();
    }

    @Override
    public List<IProxyListener> getProxyListeners() {
        throw new NotImplementedException();
    }

    @Override
    public void removeProxyListener(IProxyListener iProxyListener) {
        throw new NotImplementedException();
    }

    @Override
    public void registerScannerListener(IScannerListener iScannerListener) {
        throw new NotImplementedException();
    }

    @Override
    public List<IScannerListener> getScannerListeners() {
        throw new NotImplementedException();
    }

    @Override
    public void removeScannerListener(IScannerListener iScannerListener) {
        throw new NotImplementedException();
    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener iScopeChangeListener) {
        throw new NotImplementedException();
    }

    @Override
    public List<IScopeChangeListener> getScopeChangeListeners() {
        throw new NotImplementedException();
    }

    @Override
    public void removeScopeChangeListener(IScopeChangeListener iScopeChangeListener) {
        throw new NotImplementedException();
    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory iContextMenuFactory) {
        throw new NotImplementedException();
    }

    @Override
    public List<IContextMenuFactory> getContextMenuFactories() {
        throw new NotImplementedException();
    }

    @Override
    public void removeContextMenuFactory(IContextMenuFactory iContextMenuFactory) {
        throw new NotImplementedException();
    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {
        throw new NotImplementedException();
    }

    @Override
    public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
        throw new NotImplementedException();
    }

    @Override
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {
        throw new NotImplementedException();
    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {
        throw new NotImplementedException();
    }

    @Override
    public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
        throw new NotImplementedException();
    }

    @Override
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {
        throw new NotImplementedException();
    }

    @Override
    public void registerScannerCheck(IScannerCheck iScannerCheck) {
        throw new NotImplementedException();
    }

    @Override
    public List<IScannerCheck> getScannerChecks() {
        throw new NotImplementedException();
    }

    @Override
    public void removeScannerCheck(IScannerCheck iScannerCheck) {
        throw new NotImplementedException();
    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {
        throw new NotImplementedException();
    }

    @Override
    public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
        throw new NotImplementedException();
    }

    @Override
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {
        throw new NotImplementedException();
    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {
        throw new NotImplementedException();
    }

    @Override
    public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
        throw new NotImplementedException();
    }

    @Override
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {
        throw new NotImplementedException();
    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {
        throw new NotImplementedException();
    }

    @Override
    public List<ISessionHandlingAction> getSessionHandlingActions() {
        throw new NotImplementedException();
    }

    @Override
    public void removeSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {
        throw new NotImplementedException();
    }

    @Override
    public void unloadExtension() {
        throw new NotImplementedException();
    }

    @Override
    public void removeSuiteTab(ITab iTab) {
        throw new NotImplementedException();
    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController iMessageEditorController, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public String[] getCommandLineArguments() {
        throw new NotImplementedException();
    }

    @Override
    public void saveExtensionSetting(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public String loadExtensionSetting(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void sendToRepeater(String s, int i, boolean b, byte[] bytes, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes, List<int[]> list) {
        throw new NotImplementedException();
    }

    @Override
    public void sendToComparer(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public void sendToSpider(URL url) {
        throw new NotImplementedException();
    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes, List<int[]> list) {
        throw new NotImplementedException();
    }

    @Override
    public void doPassiveScan(String s, int i, boolean b, byte[] bytes, byte[] bytes1) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes, boolean b1) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes, boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes, boolean b, String s) {
        throw new NotImplementedException();
    }

    @Override
    public void includeInScope(URL url) {
        throw new NotImplementedException();
    }

    @Override
    public void excludeFromScope(URL url) {
        throw new NotImplementedException();
    }

    @Override
    public void issueAlert(String s) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String s) {
        throw new NotImplementedException();
    }

    @Override
    public IScanIssue[] getScanIssues(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void generateScanReport(String s, IScanIssue[] iScanIssues, File file) {
        throw new NotImplementedException();
    }

    @Override
    public List<ICookie> getCookieJarContents() {
        throw new NotImplementedException();
    }

    @Override
    public void updateCookieJar(ICookie iCookie) {
        throw new NotImplementedException();
    }

    @Override
    public void addToSiteMap(IHttpRequestResponse iHttpRequestResponse) {
        throw new NotImplementedException();
    }

    @Override
    public void restoreState(File file) {
        throw new NotImplementedException();
    }

    @Override
    public void saveState(File file) {
        throw new NotImplementedException();
    }

    @Override
    public Map<String, String> saveConfig() {
        throw new NotImplementedException();
    }

    @Override
    public void loadConfig(Map<String, String> map) {
        throw new NotImplementedException();
    }

    @Override
    public String saveConfigAsJson(String... strings) {
        throw new NotImplementedException();
    }

    @Override
    public void loadConfigFromJson(String s) {
        throw new NotImplementedException();
    }

    @Override
    public void setProxyInterceptionEnabled(boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public String[] getBurpVersion() {
        throw new NotImplementedException();
    }

    @Override
    public String getExtensionFilename() {
        throw new NotImplementedException();
    }

    @Override
    public boolean isExtensionBapp() {
        throw new NotImplementedException();
    }

    @Override
    public void exitSuite(boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public ITempFile saveToTempFile(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse iHttpRequestResponse) {
        throw new NotImplementedException();
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse iHttpRequestResponse, List<int[]> list, List<int[]> list1) {
        throw new NotImplementedException();
    }

    @Override
    public String getToolName(int i) {
        throw new NotImplementedException();
    }

    @Override
    public void addScanIssue(IScanIssue iScanIssue) {
        throw new NotImplementedException();
    }

    @Override
    public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
        throw new NotImplementedException();
    }

    @Override
    public String[][] getParameters(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public String[] getHeaders(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public void registerMenuItem(String s, IMenuItemHandler iMenuItemHandler) {
        throw new NotImplementedException();
    }
}
