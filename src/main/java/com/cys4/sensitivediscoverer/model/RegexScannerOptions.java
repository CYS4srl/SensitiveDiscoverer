package com.cys4.sensitivediscoverer.model;

import burp.api.montoya.persistence.Preferences;
import com.cys4.sensitivediscoverer.RegexSeeder;
import com.cys4.sensitivediscoverer.utils.FileUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

/**
 * Options used by the RegexScanner for modifying its behaviour
 */
public class RegexScannerOptions {
    private final Properties configProperties;
    private final Preferences burpPreferences;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;

    /**
     * Checkbox to skip responses not in scope
     */
    private boolean filterInScopeCheckbox;
    /**
     * Checkbox to skip responses over a set max size
     */
    private boolean filterSkipMaxSizeCheckbox;
    /**
     * Checkbox to skip responses of a media MIME-type
     */
    private boolean filterSkipMediaTypeCheckbox;

    /**
     * Max response size in bytes
     */
    private int configMaxResponseSize;
    /**
     * Number of threads to use to scan items
     */
    private int configNumberOfThreads;
    /**
     * The size, in bytes, of the region before the match where the refinerRegex is applied
     */
    private int configRefineContextSize;

    /**
     * @param configProperties The default options to load if persistent preferences are missing.
     * @param burpPreferences  The instance for accessing Burp Suite's functionality for persisting preferences.
     */
    public RegexScannerOptions(Properties configProperties, Preferences burpPreferences) {
        if (Objects.isNull(configProperties))
            throw new IllegalArgumentException(getLocaleString("exception-invalidProperties"));
        if (Objects.isNull(burpPreferences))
            throw new IllegalArgumentException(getLocaleString("exception-invalidPreferences"));

        this.configProperties = configProperties;
        this.burpPreferences = burpPreferences;
        this.generalRegexList = new ArrayList<>();
        this.extensionsRegexList = new ArrayList<>();

        loadOptionsDefaults();
        loadOptionsPersisted();
        loadRegexes(false);
    }

    private void loadOptionsDefaults() {
        this.setFilterInScopeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.scanner.filter.in_scope")));
        this.setFilterSkipMaxSizeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.scanner.filter.skip_max_size")));
        this.setFilterSkipMediaTypeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.scanner.filter.skip_media_type")));
        this.setConfigMaxResponseSize(Integer.parseInt(configProperties.getProperty("config.scanner.max_response_size")));
        this.setConfigNumberOfThreads(Integer.parseInt(configProperties.getProperty("config.scanner.number_of_threads")));
        this.setConfigRefineContextSize(Integer.parseInt(configProperties.getProperty("config.scanner.refine_context_size")));
    }

    private void loadOptionsPersisted() {
        this.setFilterInScopeCheckbox(burpPreferences.getBoolean("config.scanner.filter.in_scope"));
        this.setFilterSkipMaxSizeCheckbox(burpPreferences.getBoolean("config.scanner.filter.skip_max_size"));
        this.setFilterSkipMediaTypeCheckbox(burpPreferences.getBoolean("config.scanner.filter.skip_media_type"));
        this.setConfigMaxResponseSize(burpPreferences.getInteger("config.scanner.max_response_size"));
        this.setConfigNumberOfThreads(burpPreferences.getInteger("config.scanner.number_of_threads"));
        this.setConfigRefineContextSize(burpPreferences.getInteger("config.scanner.refine_context_size"));
    }

    private void loadRegexes(boolean useOnlyDefaults) {
        String json;

        this.generalRegexList.clear();
        json = burpPreferences.getString("config.scanner.general_regexes");
        if (useOnlyDefaults || Objects.isNull(json) || json.isBlank())
            this.generalRegexList.addAll(RegexSeeder.getGeneralRegexes());
        else FileUtils.importRegexListFromJSON(json, this.generalRegexList, true);

        this.extensionsRegexList.clear();
        json = burpPreferences.getString("config.scanner.extensions_regexes");
        if (useOnlyDefaults || Objects.isNull(json) || json.isBlank())
            this.extensionsRegexList.addAll(RegexSeeder.getExtensionRegexes());
        else FileUtils.importRegexListFromJSON(json, this.extensionsRegexList, true);
    }

    /**
     * Save the scanner options in Burp's persistent preference store.
     */
    public void saveToPersistentStorage() {
        burpPreferences.setInteger("config.scanner.max_response_size", this.getConfigMaxResponseSize());
        burpPreferences.setInteger("config.scanner.number_of_threads", this.getConfigNumberOfThreads());
        burpPreferences.setInteger("config.scanner.refine_context_size", this.getConfigRefineContextSize());
        burpPreferences.setBoolean("config.scanner.filter.in_scope", this.isFilterInScopeCheckbox());
        burpPreferences.setBoolean("config.scanner.filter.skip_max_size", this.isFilterSkipMaxSizeCheckbox());
        burpPreferences.setBoolean("config.scanner.filter.skip_media_type", this.isFilterSkipMediaTypeCheckbox());

        burpPreferences.setString("config.scanner.general_regexes", FileUtils.exportRegexListToJson(this.generalRegexList, true));
        burpPreferences.setString("config.scanner.extensions_regexes", FileUtils.exportRegexListToJson(this.extensionsRegexList, true));
    }

    public void resetToDefaults(boolean resetOptions, boolean resetRegexes) {
        if (resetOptions) loadOptionsDefaults();
        if (resetRegexes) loadRegexes(true);
    }

    public boolean isFilterInScopeCheckbox() {
        return filterInScopeCheckbox;
    }

    public void setFilterInScopeCheckbox(Boolean filterInScopeCheckbox) {
        if (Objects.isNull(filterInScopeCheckbox)) return;
        this.filterInScopeCheckbox = filterInScopeCheckbox;
    }

    public boolean isFilterSkipMaxSizeCheckbox() {
        return filterSkipMaxSizeCheckbox;
    }

    public void setFilterSkipMaxSizeCheckbox(Boolean filterSkipMaxSizeCheckbox) {
        if (Objects.isNull(filterSkipMaxSizeCheckbox)) return;
        this.filterSkipMaxSizeCheckbox = filterSkipMaxSizeCheckbox;
    }

    public boolean isFilterSkipMediaTypeCheckbox() {
        return filterSkipMediaTypeCheckbox;
    }

    public void setFilterSkipMediaTypeCheckbox(Boolean filterSkipMediaTypeCheckbox) {
        if (Objects.isNull(filterSkipMediaTypeCheckbox)) return;
        this.filterSkipMediaTypeCheckbox = filterSkipMediaTypeCheckbox;
    }

    public int getConfigMaxResponseSize() {
        return configMaxResponseSize;
    }

    public void setConfigMaxResponseSize(Integer configMaxResponseSize) {
        if (Objects.isNull(configMaxResponseSize)) return;
        this.configMaxResponseSize = configMaxResponseSize;
    }

    public int getConfigNumberOfThreads() {
        return configNumberOfThreads;
    }

    public void setConfigNumberOfThreads(Integer configNumberOfThreads) {
        if (Objects.isNull(configNumberOfThreads)) return;
        this.configNumberOfThreads = configNumberOfThreads;
    }

    public int getConfigRefineContextSize() {
        return configRefineContextSize;
    }

    public void setConfigRefineContextSize(Integer configRefineContextSize) {
        if (Objects.isNull(configRefineContextSize)) return;
        this.configRefineContextSize = configRefineContextSize;
    }

    public List<RegexEntity> getGeneralRegexList() {
        return generalRegexList;
    }

    public List<RegexEntity> getExtensionsRegexList() {
        return extensionsRegexList;
    }
}
