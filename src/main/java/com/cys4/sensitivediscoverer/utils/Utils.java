package com.cys4.sensitivediscoverer.utils;

import burp.api.montoya.MontoyaApi;
import com.cys4.sensitivediscoverer.RegexSeeder;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.RegexScannerOptions;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;


/**
 * Utils package
 */
public class Utils {

    /**
     * Read the content of a resource file.
     *
     * @param filepath Path to the resource file.
     * @return A UTF-8 string with the content of the file read.
     */
    public static String readResourceFile(String filepath) {
        try {
            InputStream inputStream = Utils.getResourceAsStream(filepath);
            if (Objects.isNull(inputStream)) return null;

            InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr);

            return reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Properties loadConfigFile() throws Exception {
        Properties properties;

        InputStream input = Utils.getResourceAsStream("config.properties");
        properties = new Properties();
        properties.load(input);
        return properties;
    }

    /**
     * Load scanner options from the Burp preferences store.
     *
     * @param burpApi          The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @param configProperties The default options to load if persistent preferences are missing.
     * @return The loaded scanner options object.
     */
    public static RegexScannerOptions loadScannerOptions(MontoyaApi burpApi, Properties configProperties) {
        RegexScannerOptions scannerOptions = new RegexScannerOptions();

        if (burpApi.persistence().preferences().integerKeys().contains("config.max_response_size"))
            scannerOptions.setConfigMaxResponseSize(burpApi.persistence().preferences().getInteger("config.max_response_size"));
        else
            scannerOptions.setConfigMaxResponseSize(Integer.parseInt(configProperties.getProperty("config.max_response_size")));

        if (burpApi.persistence().preferences().integerKeys().contains("config.number_of_threads"))
            scannerOptions.setConfigNumberOfThreads(burpApi.persistence().preferences().getInteger("config.number_of_threads"));
        else
            scannerOptions.setConfigNumberOfThreads(Integer.parseInt(configProperties.getProperty("config.number_of_threads")));

        if (burpApi.persistence().preferences().integerKeys().contains("config.scanner.refine_context_size"))
            scannerOptions.setConfigRefineContextSize(burpApi.persistence().preferences().getInteger("config.scanner.refine_context_size"));
        else
            scannerOptions.setConfigRefineContextSize(Integer.parseInt(configProperties.getProperty("config.scanner.refine_context_size")));

        if (burpApi.persistence().preferences().booleanKeys().contains("config.filter.in_scope"))
            scannerOptions.setFilterInScopeCheckbox(burpApi.persistence().preferences().getBoolean("config.filter.in_scope"));
        else
            scannerOptions.setFilterInScopeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.filter.in_scope")));

        if (burpApi.persistence().preferences().booleanKeys().contains("config.filter.skip_max_size"))
            scannerOptions.setFilterSkipMaxSizeCheckbox(burpApi.persistence().preferences().getBoolean("config.filter.skip_max_size"));
        else
            scannerOptions.setFilterSkipMaxSizeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.filter.skip_max_size")));

        if (burpApi.persistence().preferences().booleanKeys().contains("config.filter.skip_media_type"))
            scannerOptions.setFilterSkipMediaTypeCheckbox(burpApi.persistence().preferences().getBoolean("config.filter.skip_media_type"));
        else
            scannerOptions.setFilterSkipMediaTypeCheckbox(Boolean.parseBoolean(configProperties.getProperty("config.filter.skip_media_type")));

        return scannerOptions;
    }


    /**
     * Save the scanner options in the Burp preference store.
     *
     * @param burpApi        The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @param scannerOptions The options to save.
     */
    public static void saveScannerOptions(MontoyaApi burpApi, RegexScannerOptions scannerOptions) {
        burpApi.persistence().preferences().setInteger("config.max_response_size", scannerOptions.getConfigMaxResponseSize());
        burpApi.persistence().preferences().setInteger("config.number_of_threads", scannerOptions.getConfigNumberOfThreads());
        burpApi.persistence().preferences().setInteger("config.scanner.refine_context_size", scannerOptions.getConfigRefineContextSize());
        burpApi.persistence().preferences().setBoolean("config.filter.in_scope", scannerOptions.isFilterInScopeCheckbox());
        burpApi.persistence().preferences().setBoolean("config.filter.skip_max_size", scannerOptions.isFilterSkipMaxSizeCheckbox());
        burpApi.persistence().preferences().setBoolean("config.filter.skip_media_type", scannerOptions.isFilterSkipMediaTypeCheckbox());
    }

    /**
     * Reads the regexes file name from the Burp preferences store and imports it.
     * Loads the default general regex list in case of errors.
     *
     * @param burpApi The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @return The loaded list of regexes.
     */
    public static List<RegexEntity> loadRegexList(MontoyaApi burpApi) {
        List<RegexEntity> regexEntities = new ArrayList<>();

        try {
            String fileName = burpApi.persistence().preferences().getString("config.regex_list_file_name");
            FileUtils.importRegexListFromFile(fileName, regexEntities);
        } catch (Exception e) {
            regexEntities = RegexSeeder.getGeneralRegexes();
        }

        return regexEntities;
    }

    /**
     * Save the current regex list in a Json file and its name in the Burp preference store.
     *
     * @param burpApi       The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @param regexEntities The regex list to save.
     */
    public static void saveRegexList(MontoyaApi burpApi, List<RegexEntity> regexEntities) {
        String defaultFileName = "current_regex_list.json";
        burpApi.persistence().preferences().setString("config.regex_list_file_name", defaultFileName);
        FileUtils.exportRegexListToFileJSON(defaultFileName, regexEntities);
    }

    /**
     * Reads the extensions regexes file name from the Burp preferences store and imports it.
     * Loads the default extensions regex list in case of errors.
     *
     * @param burpApi The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @return The loaded list of extensions regexes.
     */
    public static List<RegexEntity> loadExtensionsRegexList(MontoyaApi burpApi) {
        List<RegexEntity> extensionsRegexEntities = new ArrayList<>();

        try {
            String fileName = burpApi.persistence().preferences().getString("config.extensions_regex_list_file_name");
            FileUtils.importRegexListFromFile(fileName, extensionsRegexEntities);
        } catch (Exception e) {
            extensionsRegexEntities = RegexSeeder.getExtensionRegexes();
        }

        return extensionsRegexEntities;
    }

    /**
     * Save the current extensions regex list in a Json file and its name in the Burp preference store.
     *
     * @param burpApi                 The MontoyaApi instance for accessing Burp Suite preference store functionality.
     * @param extensionsRegexEntities The regex list to save.
     */
    public static void saveExtensionsRegexList(MontoyaApi burpApi, List<RegexEntity> extensionsRegexEntities) {
        String defaultFileName = "current_extensions_regex_list.json";
        burpApi.persistence().preferences().setString("config.extensions_regex_list_file_name", defaultFileName);
        FileUtils.exportRegexListToFileJSON(defaultFileName, extensionsRegexEntities);
    }

    public static String getExtensionVersion() {
        return Utils.class.getPackage().getImplementationVersion();
    }

    /**
     * Returns an input stream for reading the specified resource.
     *
     * @param name The resource name
     * @return An input stream for reading the resource; null if the resource could not be found or there was an error.
     */
    public static InputStream getResourceAsStream(String name) {
        return Utils.class.getClassLoader().getResourceAsStream(name);
    }

    /**
     * Creates and configures a new {@link Gson} instance for JSON processing.
     *
     * @return A new {@link Gson} instance with HTML escaping disabled.
     */
    public static Gson createGsonBuilder() {
        return new GsonBuilder()
                .disableHtmlEscaping()
                .create();
    }
}
