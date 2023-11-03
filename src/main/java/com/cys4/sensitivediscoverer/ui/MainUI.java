/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.scanner.BurpLeaksScanner;
import com.cys4.sensitivediscoverer.seed.RegexSeeder;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class MainUI implements ITab {
    /**
     * Checkbox to skip responses not in scope
     */
    static boolean inScopeCheckbox = false;
    /**
     * Checkbox to skip responses over a set max size
     */
    static boolean skipMaxSizeCheckbox = true;
    /**
     * Checkbox to skip responses of a media MIME-type
     */
    static boolean skipMediaTypeCheckbox = true;

    private final IBurpExtenderCallbacks callbacks;
    private final List<LogEntity> logEntries;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;
    private final BurpLeaksScanner burpLeaksScanner;
    private Properties configProperties;

    // ui components
    private JTabbedPane mainPanel;
    private LogTableEntriesUI logTableEntriesUI;

    /**
     * Max response size in bytes
     */
    private int maxSizeValue;

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // setup stdout/stderr
        System.setOut(new PrintStream(callbacks.getStdout(), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(callbacks.getStderr(), true, StandardCharsets.UTF_8));

        loadConfigFile();
        this.maxSizeValue = Integer.parseInt(configProperties.getProperty("config.max_response_size"));

        this.generalRegexList = RegexSeeder.getGeneralRegexes();
        this.extensionsRegexList = RegexSeeder.getExtensionRegexes();

        // Logger elements
        this.logEntries = new ArrayList<>();
        this.burpLeaksScanner = new BurpLeaksScanner(
                Integer.parseInt(configProperties.getProperty("config.number_of_threads")),
                this,
                callbacks,
                logEntries,
                this.generalRegexList,
                this.extensionsRegexList);
    }

    /**
     * returns true if the option checkbox is selected
     */
    public static boolean isInScopeOptionSelected() {
        return inScopeCheckbox;
    }

    /**
     * returns true if the option checkbox is selected
     */
    public static boolean isSkipMaxSizeOptionSelected() {
        return skipMaxSizeCheckbox;
    }

    /**
     * returns true if the option checkbox is selected
     */
    public static boolean isSkipMediaTypeOptionSelected() {
        return skipMediaTypeCheckbox;
    }

    private void loadConfigFile() {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("config.properties")) {
            assert (input != null);

            configProperties = new Properties();
            configProperties.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * TODO: replace
     * notifies logTablesEntriesUI of a newly added row
     */
    public void logTableEntriesUIAddNewRow(int row) {
        logTableEntriesUI.addNewRow(row);
    }

    /**
     * Main function that initializes the extension and creates the UI, asynchronously
     */
    public void initialize() {
        SwingUtilities.invokeLater(this::_initialize);
    }

    private void _initialize() {
        mainPanel = new JTabbedPane();
        LoggerTab loggerTab = new LoggerTab(this);
        mainPanel.addTab(loggerTab.getTabName(), loggerTab.getPanel());
        ApplicationTab optionsTab = new OptionsTab(this);
        mainPanel.addTab(optionsTab.getTabName(), optionsTab.getPanel());
        ApplicationTab aboutTab = new AboutTab();
        mainPanel.addTab(aboutTab.getTabName(), aboutTab.getPanel());

        logTableEntriesUI = loggerTab.getLogTableEntriesUI();

        callbacks.customizeUiComponent(mainPanel);
        callbacks.addSuiteTab(MainUI.this);
    }

    /**
     * Returns the extension's main panel
     */
    public JTabbedPane getMainPanel() {
        return mainPanel;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public List<LogEntity> getLogEntries() {
        return logEntries;
    }

    public List<RegexEntity> getGeneralRegexList() {
        return generalRegexList;
    }

    public List<RegexEntity> getExtensionsRegexList() {
        return extensionsRegexList;
    }

    /**
     * Returns the burpLeaksScanner instance used for scanning log entries
     */
    public BurpLeaksScanner getBurpLeaksScanner() {
        return burpLeaksScanner;
    }

    /**
     * GetNameExtension return the name of the extension from the configuration file
     */
    public String getNameExtension() {
        return configProperties.getProperty("ui.extension_name");
    }

    /**
     * Returns the set max size for responses
     */
    public int getMaxSizeValueOption() {
        return maxSizeValue;
    }

    public void setMaxSizeValueOption(int newMaxSizeValue) {
        this.maxSizeValue = newMaxSizeValue;
    }

    @Override
    public String getTabCaption() {
        return getNameExtension();
    }

    @Override
    public Component getUiComponent() {
        return getMainPanel();
    }
}
