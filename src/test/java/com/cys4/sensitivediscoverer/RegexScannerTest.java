package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.mock.*;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.ProxyItemSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

class RegexScannerTest {
    private final List<RegexEntity> generalRegexList = List.of();
    private final List<RegexEntity> extensionsRegexList = List.of();
    private RegexScanner regexScanner;
    private BurpExtenderCallbacksMock burpExtenderCallbacks;
    private ExtensionHelpersMock extensionHelpers;
    private ScannerOptions scannerOptions;

    private static void accept(Integer integer) {
    }

    private byte[] B(String str) {
        return str.getBytes(StandardCharsets.UTF_8);
    }

    private HttpRequestResponseMock HRR(String req, String res) {
        return new HttpRequestResponseMock(B(req), B(res));
    }

    @BeforeEach
    void setUp() {
        extensionHelpers = new ExtensionHelpersMock();
        //TODO missing way to test url & headers
        extensionHelpers.setAnalyzeRequestFunction(httpRequestResponse -> {
            try {
                return new RequestInfoMock(List.of(), new URL("https://null"));
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        });
        //TODO missing way to test headers
        extensionHelpers.setAnalyzeResponseFunction(response -> new ResponseInfoMock(List.of()));
        extensionHelpers.setBytesToStringFunction(bytes -> new String(bytes, StandardCharsets.UTF_8));
        burpExtenderCallbacks = new BurpExtenderCallbacksMock();
        burpExtenderCallbacks.setHelpers(extensionHelpers);

        scannerOptions = new ScannerOptions();
        scannerOptions.setConfigMaxResponseSize(10000000);
        scannerOptions.setConfigNumberOfThreads(1);
        scannerOptions.setFilterInScopeCheckbox(false);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);

        this.regexScanner = new RegexScanner(burpExtenderCallbacks, scannerOptions, generalRegexList, extensionsRegexList);
    }

    @Test
    void testAnalysisOfGeneralRegexes() {
        final List<LogEntity> logEntities = new ArrayList<>();
        final Object loggerLock = new Object();

        // set-up callbacks
        Consumer<Integer> itemAnalyzedCallback = RegexScannerTest::accept;
        Consumer<LogEntity> logEntityConsumer = logEntity -> {
            synchronized (loggerLock) {
                logEntities.add(logEntity);
            }
        };
        // set-up BurpExtenderCallbacks
        this.burpExtenderCallbacks.setIsInScopePredicate(url -> true);
        HttpRequestResponseMock[] proxyHistory = {
                HRR("testing", "testing")
        };
        this.burpExtenderCallbacks.setProxyHistory(proxyHistory);

        // test 1
        logEntities.clear();
        this.regexScanner = new RegexScanner(this.burpExtenderCallbacks, this.scannerOptions,
                List.of(
                        new RegexEntity("Match test string", "test", true, ProxyItemSection.ALL)
                ),
                List.of());
        regexScanner.analyzeProxyHistory(itemAnalyzedCallback, logEntityConsumer);
        assertThat(logEntities).as("Check count of entries found").hasSize(2);

        // test 2
        logEntities.clear();
        this.regexScanner = new RegexScanner(this.burpExtenderCallbacks, this.scannerOptions,
                List.of(
                        new RegexEntity("Match random string", "random", true, ProxyItemSection.ALL)
                ),
                List.of());
        regexScanner.analyzeProxyHistory(itemAnalyzedCallback, logEntityConsumer);
        assertThat(logEntities).as("Check count of entries found").hasSize(0);
    }
}