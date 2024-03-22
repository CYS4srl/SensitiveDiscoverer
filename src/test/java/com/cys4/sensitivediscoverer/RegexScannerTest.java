package com.cys4.sensitivediscoverer;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.cys4.sensitivediscoverer.mock.BurpMontoyaApiMock;
import com.cys4.sensitivediscoverer.mock.ProxyHttpRequestResponseMock;
import com.cys4.sensitivediscoverer.mock.ProxyMock;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class RegexScannerTest {
    private final List<RegexEntity> generalRegexList = List.of();
    private final List<RegexEntity> extensionsRegexList = List.of();
    private RegexScanner regexScanner;
    private BurpMontoyaApiMock burpApi;
    private ScannerOptions scannerOptions;
    private List<LogEntity> logEntries;
    private Function<Integer, Runnable> progressBarCallbackSetupMock;
    private Consumer<LogEntity> logEntityConsumer;

    @BeforeEach
    void setUp() {
        burpApi = new BurpMontoyaApiMock();

        //TODO test scanner options
        scannerOptions = new ScannerOptions();
        scannerOptions.setConfigMaxResponseSize(10000000);
        scannerOptions.setConfigNumberOfThreads(1);
        scannerOptions.setFilterInScopeCheckbox(false);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);

        this.regexScanner = new RegexScanner(burpApi, scannerOptions, generalRegexList, extensionsRegexList);
    }

    @BeforeEach
    void setUpCallbacks() {
        this.logEntries = new ArrayList<>();
        final Object loggerLock = new Object();

        progressBarCallbackSetupMock = (maxItems) -> () -> {
        };
        //TODO logEntityConsumer should use LoggerTab::addLogEntry instead of re-implementing it
        logEntityConsumer = logEntry -> {
            synchronized (loggerLock) {
                if (!logEntries.contains(logEntry)) {
                    logEntries.add(logEntry);
                }
            }
        };
    }

    //TODO: test matching of specific sections

    @Test
    void testGeneralRegexesWithFindings() {
        this.setProxyHistory(
                new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT"),
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT")
        );

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                List.of(
                        new RegexEntity("Match test string", "test", true, HttpSection.ALL)
                ),
                List.of());
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);
        assertThat(logEntries).as("Check count of entries found").hasSize(2);
    }

    @Test
    void testGeneralRegexesNoDuplicatesInFindings() {
        this.setProxyHistory(
                new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT"),
                new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT"),
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT"),
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT")
        );

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                List.of(
                        new RegexEntity("Match test string", "test", true, HttpSection.ALL)
                ),
                List.of());
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);
        assertThat(logEntries).as("Check duplicates aren't inserted more than once").hasSize(2);
    }

    @Test
    void testGeneralRegexesNoFindings() {
        this.setProxyHistory(
                new ProxyHttpRequestResponseMock("testing", "testing"),
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2")
        );

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                List.of(
                        new RegexEntity("Match random string", "random", true, HttpSection.ALL)
                ),
                List.of());
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);
        assertThat(logEntries).as("Check count of entries found").hasSize(0);
    }

    void setProxyHistory(ProxyHttpRequestResponseMock... proxyElements) {
        List<ProxyHttpRequestResponse> proxyHistory = new ArrayList<>(Arrays.asList(proxyElements));
        ((ProxyMock) this.burpApi.proxy()).setHistory(proxyHistory);
    }
}