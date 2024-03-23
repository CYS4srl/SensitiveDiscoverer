package com.cys4.sensitivediscoverer;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.cys4.sensitivediscoverer.mock.BurpMontoyaApiMock;
import com.cys4.sensitivediscoverer.mock.ProxyHttpRequestResponseMock;
import com.cys4.sensitivediscoverer.mock.ProxyMock;
import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import com.cys4.sensitivediscoverer.utils.LoggerUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class RegexScannerTest {
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
        scannerOptions.setConfigRefineContextSize(64);
        scannerOptions.setFilterInScopeCheckbox(false);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);
    }

    @BeforeEach
    void setUpCallbacks() {
        this.logEntries = new ArrayList<>();
        final Object loggerLock = new Object();

        progressBarCallbackSetupMock = (maxItems) -> () -> {
        };
        logEntityConsumer = LoggerUtils.createAddLogEntryCallback(logEntries, loggerLock, Optional.empty());
    }

    @Test
    void testGeneralRegexesWithFindings() {
        ProxyHttpRequestResponseMock request1 = new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT");
        ProxyHttpRequestResponseMock request2 = new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT");
        this.setProxyHistory(request1, request2);

        List<RegexEntity> generalRegexes = List.of(
                new RegexEntity("Match test string", "test.{0,10}", true, HttpSection.ALL, ""));
        List<RegexEntity> extensionsRegexes = List.of();

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                generalRegexes,
                extensionsRegexes);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);

        assertThat(logEntries).as("Check count of entries found").hasSize(10);
        assertThat(logEntries).containsExactly(
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_URL, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_HEADERS, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_BODY, "testing 2"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.RES_HEADERS, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.RES_BODY, "testing 2"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_URL, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_HEADERS, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_BODY, "testing"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.RES_HEADERS, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.RES_BODY, "testing")
        );
    }

    @Test
    void testGeneralRegexesNoDuplicatesInFindings() {
        ProxyHttpRequestResponseMock request1 = new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT");
        ProxyHttpRequestResponseMock request2 = new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT");
        this.setProxyHistory(
                request1,
                new ProxyHttpRequestResponseMock("testing", "testing", "Mon, 01 Jan 1990 10:00:00 GMT"),
                request2,
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2", "Mon, 01 Jan 1990 10:00:01 GMT")
        );

        List<RegexEntity> generalRegexes = List.of(
                new RegexEntity("Match test string", "test.{0,10}", true, HttpSection.ALL, ""));
        List<RegexEntity> extensionsRegexes = List.of();

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                generalRegexes,
                extensionsRegexes);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);

        assertThat(logEntries).as("Check duplicates aren't inserted more than once").hasSize(10);
        assertThat(logEntries).containsExactly(
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_URL, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_HEADERS, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.REQ_BODY, "testing 2"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.RES_HEADERS, "test.com"),
                new LogEntity(request2.finalRequest(), request2.response(), generalRegexes.get(0), HttpSection.RES_BODY, "testing 2"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_URL, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_HEADERS, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.REQ_BODY, "testing"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.RES_HEADERS, "test.com"),
                new LogEntity(request1.finalRequest(), request1.response(), generalRegexes.get(0), HttpSection.RES_BODY, "testing")
        );
    }

    @Test
    void testGeneralRegexesNoFindings() {
        this.setProxyHistory(
                new ProxyHttpRequestResponseMock("testing", "testing"),
                new ProxyHttpRequestResponseMock("a testing 2", "a testing 2")
        );

        List<RegexEntity> generalRegexes = List.of(
                new RegexEntity("Match random string", "random", true, HttpSection.ALL, "")
        );
        List<RegexEntity> extensionsRegexes = List.of();

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                generalRegexes,
                extensionsRegexes);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);

        assertThat(logEntries).as("Check count of entries found").hasSize(0);
    }

    private void setProxyHistory(ProxyHttpRequestResponseMock... proxyElements) {
        List<ProxyHttpRequestResponse> proxyHistory = new ArrayList<>(Arrays.asList(proxyElements));
        ((ProxyMock) this.burpApi.proxy()).setHistory(proxyHistory);
    }

    @Test
    void testRefinerRegex() {
        ProxyHttpRequestResponseMock request = new ProxyHttpRequestResponseMock("randomstring.example.com", "bucket-name.test.example.com", "Mon, 01 Jan 1990 10:00:00 GMT");
        this.setProxyHistory(request);

        List<RegexEntity> generalRegexes = List.of(
                new RegexEntity("Find subdomains of example.com", "example\\.com", true, HttpSection.ALL, "[a-z\\-\\.]{3,64}\\.$"));
        List<RegexEntity> extensionsRegexes = List.of();

        this.regexScanner = new RegexScanner(this.burpApi, this.scannerOptions,
                generalRegexes,
                extensionsRegexes);
        regexScanner.analyzeProxyHistory(progressBarCallbackSetupMock, logEntityConsumer);

        assertThat(logEntries).as("Check count of entries found").hasSize(2);
        assertThat(logEntries).containsExactly(
                new LogEntity(request.finalRequest(), request.response(), generalRegexes.get(0), HttpSection.REQ_BODY, "randomstring.example.com"),
                new LogEntity(request.finalRequest(), request.response(), generalRegexes.get(0), HttpSection.RES_BODY, "bucket-name.test.example.com")
        );
    }
}