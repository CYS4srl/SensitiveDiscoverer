package com.cys4.sensitivediscoverer.model;

import com.cys4.sensitivediscoverer.RegexSeeder;
import com.cys4.sensitivediscoverer.mock.PreferencesMock;
import com.cys4.sensitivediscoverer.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class RegexScannerOptionsTest {
    private RegexScannerOptions scannerOptions;

    @BeforeEach
    void setUp() throws Exception {
        scannerOptions = new RegexScannerOptions(Utils.loadConfigFile(), new PreferencesMock());

        assertThat(scannerOptions.getConfigMaxResponseSize()).isEqualTo(10000000);
        assertThat(scannerOptions.getConfigNumberOfThreads()).isEqualTo(4);
        assertThat(scannerOptions.getConfigRefineContextSize()).isEqualTo(64);
        assertThat(scannerOptions.isFilterInScopeCheckbox()).isFalse();
        assertThat(scannerOptions.isFilterSkipMaxSizeCheckbox()).isTrue();
        assertThat(scannerOptions.isFilterSkipMediaTypeCheckbox()).isTrue();
    }

    @Test
    void testResetDefaultOptions() {
        testChangeOptions();

        scannerOptions.resetToDefaults(true, false);

        assertThat(scannerOptions.getConfigMaxResponseSize()).isEqualTo(10000000);
        assertThat(scannerOptions.getConfigNumberOfThreads()).isEqualTo(4);
        assertThat(scannerOptions.getConfigRefineContextSize()).isEqualTo(64);
        assertThat(scannerOptions.isFilterInScopeCheckbox()).isFalse();
        assertThat(scannerOptions.isFilterSkipMaxSizeCheckbox()).isTrue();
        assertThat(scannerOptions.isFilterSkipMediaTypeCheckbox()).isTrue();
    }

    @Test
    void testChangeOptions() {
        scannerOptions.setConfigMaxResponseSize(9999999);
        scannerOptions.setConfigNumberOfThreads(2);
        scannerOptions.setConfigRefineContextSize(128);
        scannerOptions.setFilterInScopeCheckbox(true);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);

        assertThat(scannerOptions.getConfigMaxResponseSize()).isEqualTo(9999999);
        assertThat(scannerOptions.getConfigNumberOfThreads()).isEqualTo(2);
        assertThat(scannerOptions.getConfigRefineContextSize()).isEqualTo(128);
        assertThat(scannerOptions.isFilterInScopeCheckbox()).isTrue();
        assertThat(scannerOptions.isFilterSkipMaxSizeCheckbox()).isFalse();
        assertThat(scannerOptions.isFilterSkipMediaTypeCheckbox()).isFalse();
    }

    @Test
    void testResetRegexList() {
        testChangeRegexList();
        scannerOptions.resetToDefaults(false, true);
        assertThat(scannerOptions.getGeneralRegexList()).isEqualTo(RegexSeeder.getGeneralRegexes());
    }

    @Test
    void testChangeRegexList() {
        scannerOptions.getGeneralRegexList().clear();
        assertThat(scannerOptions.getGeneralRegexList()).isEmpty();
    }

    @Test
    void testResetExtensionRegexList() {
        testChangeExtensionRegexList();
        scannerOptions.resetToDefaults(false, true);
        assertThat(scannerOptions.getExtensionsRegexList()).isEqualTo(RegexSeeder.getExtensionRegexes());
    }

    @Test
    void testChangeExtensionRegexList() {
        scannerOptions.getExtensionsRegexList().clear();
        assertThat(scannerOptions.getExtensionsRegexList()).isEmpty();
    }
}
