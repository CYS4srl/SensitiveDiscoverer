package com.cys4.sensitivediscoverer.model;

import burp.api.montoya.persistence.Preferences;
import com.cys4.sensitivediscoverer.RegexSeeder;
import com.cys4.sensitivediscoverer.mock.PreferencesMock;
import com.cys4.sensitivediscoverer.utils.FileUtils;
import com.cys4.sensitivediscoverer.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class RegexScannerOptionsTest {
    private RegexScannerOptions scannerOptions;
    private PreferencesMock burpPreferences;
    private Properties configProperties;

    @BeforeEach
    void setUp() throws Exception {
        this.configProperties = Utils.loadConfigFile();
        this.burpPreferences = new PreferencesMock();
        this.scannerOptions = new RegexScannerOptions(configProperties, burpPreferences);
    }

    @Test
    void testInvalidScannerOptions() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexScannerOptions(null, new PreferencesMock()));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexScannerOptions(new Properties(), null));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexScannerOptions(null, null));
    }

    @Test
    void testDefaultsOptions() {
        assertThat(scannerOptions.getConfigMaxResponseSize()).isGreaterThan(1000);
        assertThat(scannerOptions.getConfigNumberOfThreads()).isGreaterThanOrEqualTo(1);
        assertThat(scannerOptions.getConfigNumberOfThreads()).isLessThanOrEqualTo(128);
        assertThat(scannerOptions.getConfigRefineContextSize()).isGreaterThanOrEqualTo(16);
        assertThat(scannerOptions.getConfigRefineContextSize()).isLessThanOrEqualTo(16384);
        assertThat(scannerOptions.isFilterInScopeCheckbox()).isFalse();
        assertThat(scannerOptions.isFilterSkipMaxSizeCheckbox()).isTrue();
        assertThat(scannerOptions.isFilterSkipMediaTypeCheckbox()).isTrue();
    }

    @Test
    void testResetDefaultOptions() {
        scannerOptions.setConfigMaxResponseSize(9999999);
        scannerOptions.setConfigNumberOfThreads(2);
        scannerOptions.setConfigRefineContextSize(128);
        scannerOptions.setFilterInScopeCheckbox(true);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);
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
        scannerOptions.getGeneralRegexList().clear();
        scannerOptions.resetToDefaults(false, true);
        assertThat(scannerOptions.getGeneralRegexList()).containsExactlyInAnyOrderElementsOf(RegexSeeder.getGeneralRegexes());
    }

    @Test
    void testChangeRegexList() {
        scannerOptions.getGeneralRegexList().clear();
        assertThat(scannerOptions.getGeneralRegexList()).isEmpty();
    }

    @Test
    void testResetExtensionRegexList() {
        scannerOptions.getExtensionsRegexList().clear();
        scannerOptions.resetToDefaults(false, true);
        assertThat(scannerOptions.getExtensionsRegexList()).containsExactlyInAnyOrderElementsOf(RegexSeeder.getExtensionRegexes());
    }

    @Test
    void testChangeExtensionRegexList() {
        scannerOptions.getExtensionsRegexList().clear();
        assertThat(scannerOptions.getExtensionsRegexList()).isEmpty();
    }

    @Test
    void testPersistedOptionsLoading() {
        Preferences burpPreferences = new PreferencesMock();
        burpPreferences.setInteger("config.scanner.max_response_size", 9999999);
        burpPreferences.setInteger("config.scanner.number_of_threads", 2);
        burpPreferences.setInteger("config.scanner.refine_context_size", 128);
        burpPreferences.setBoolean("config.scanner.filter.in_scope", true);
        burpPreferences.setBoolean("config.scanner.filter.skip_max_size", false);
        burpPreferences.setBoolean("config.scanner.filter.skip_media_type", false);

        RegexScannerOptions newOptions = new RegexScannerOptions(configProperties, burpPreferences);
        assertThat(newOptions.getConfigMaxResponseSize()).isEqualTo(9999999);
        assertThat(newOptions.getConfigNumberOfThreads()).isEqualTo(2);
        assertThat(newOptions.getConfigRefineContextSize()).isEqualTo(128);
        assertThat(newOptions.isFilterInScopeCheckbox()).isTrue();
        assertThat(newOptions.isFilterSkipMaxSizeCheckbox()).isFalse();
        assertThat(newOptions.isFilterSkipMediaTypeCheckbox()).isFalse();
    }

    @Test
    void testPersistedRegexesLoading() {
        List<RegexEntity> regexes = List.of(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // all
                new RegexEntity("Test regex 2", "-----BEGIN", false, HttpSection.RES, ".+$"),
                // empty section; no refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), null),
                // all
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$")
        );
        String regexesJson = FileUtils.exportRegexListToJson(regexes, true);

        Preferences burpPreferences = new PreferencesMock();
        burpPreferences.setString("config.scanner.general_regexes", regexesJson);
        burpPreferences.setString("config.scanner.extensions_regexes", regexesJson);

        RegexScannerOptions newOptions = new RegexScannerOptions(configProperties, burpPreferences);
        assertThat(newOptions.getGeneralRegexList()).containsExactlyInAnyOrderElementsOf(regexes);
        assertThat(newOptions.getExtensionsRegexList()).containsExactlyInAnyOrderElementsOf(regexes);
    }

    @Test
    void testEmptyPersistedRegexesLoading() {
        Preferences burpPreferences = new PreferencesMock();
        burpPreferences.setString("config.scanner.general_regexes", "");
        burpPreferences.setString("config.scanner.extensions_regexes", "");

        RegexScannerOptions newOptions = new RegexScannerOptions(configProperties, burpPreferences);
        assertThat(newOptions.getGeneralRegexList()).containsExactlyInAnyOrderElementsOf(RegexSeeder.getGeneralRegexes());
        assertThat(newOptions.getExtensionsRegexList()).containsExactlyInAnyOrderElementsOf(RegexSeeder.getExtensionRegexes());
    }

    @Test
    void testSaveToPersistentStorage() {
        List<RegexEntity> regexes = List.of(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // all
                new RegexEntity("Test regex 2", "-----BEGIN", false, HttpSection.RES, ".+$"),
                // empty section; no refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), null),
                // all
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$")
        );
        scannerOptions.setConfigMaxResponseSize(9999999);
        scannerOptions.setConfigNumberOfThreads(2);
        scannerOptions.setConfigRefineContextSize(128);
        scannerOptions.setFilterInScopeCheckbox(true);
        scannerOptions.setFilterSkipMaxSizeCheckbox(false);
        scannerOptions.setFilterSkipMediaTypeCheckbox(false);
        scannerOptions.getGeneralRegexList().clear();
        scannerOptions.getGeneralRegexList().addAll(regexes);
        scannerOptions.getExtensionsRegexList().clear();
        scannerOptions.getExtensionsRegexList().addAll(regexes);

        scannerOptions.saveToPersistentStorage();
        RegexScannerOptions newOptions = new RegexScannerOptions(configProperties, burpPreferences);
        assertThat(newOptions.getConfigMaxResponseSize()).isEqualTo(9999999);
        assertThat(newOptions.getConfigNumberOfThreads()).isEqualTo(2);
        assertThat(newOptions.getConfigRefineContextSize()).isEqualTo(128);
        assertThat(newOptions.isFilterInScopeCheckbox()).isTrue();
        assertThat(newOptions.isFilterSkipMaxSizeCheckbox()).isFalse();
        assertThat(newOptions.isFilterSkipMediaTypeCheckbox()).isFalse();
        assertThat(newOptions.getGeneralRegexList()).containsExactlyInAnyOrderElementsOf(regexes);
        assertThat(newOptions.getExtensionsRegexList()).containsExactlyInAnyOrderElementsOf(regexes);
    }
}
