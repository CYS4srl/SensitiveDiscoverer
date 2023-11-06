/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import com.cys4.sensitivediscoverer.tab.AboutTab;
import com.cys4.sensitivediscoverer.tab.ApplicationTab;
import com.cys4.sensitivediscoverer.tab.LoggerTab;
import com.cys4.sensitivediscoverer.tab.OptionsTab;

import javax.swing.*;
import java.awt.*;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

import static com.cys4.sensitivediscoverer.Utils.loadConfigFile;

public class MainUI implements ITab {
    private final IBurpExtenderCallbacks callbacks;
    private final List<RegexEntity> generalRegexList;
    private final List<RegexEntity> extensionsRegexList;
    private final RegexScanner regexScanner;
    private final Properties configProperties;
    private final ScannerOptions scannerOptions;

    // ui components
    private JTabbedPane mainPanel;

    public MainUI(IBurpExtenderCallbacks callbacks) throws Exception {

        this.callbacks = callbacks;

        // setup stdout/stderr
        System.setOut(new PrintStream(callbacks.getStdout(), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(callbacks.getStderr(), true, StandardCharsets.UTF_8));

        this.configProperties = loadConfigFile();
        scannerOptions = new ScannerOptions();
        scannerOptions.setConfigMaxResponseSize(Integer.parseInt(configProperties.getProperty("config.max_response_size")));
        scannerOptions.setConfigNumberOfThreads(Integer.parseInt(configProperties.getProperty("config.number_of_threads")));

        this.generalRegexList = RegexSeeder.getGeneralRegexes();
        this.extensionsRegexList = RegexSeeder.getExtensionRegexes();

        // Logger elements
        this.regexScanner = new RegexScanner(
                this,
                scannerOptions,
                this.generalRegexList,
                this.extensionsRegexList);
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
        ApplicationTab optionsTab = new OptionsTab(this, scannerOptions);
        mainPanel.addTab(optionsTab.getTabName(), optionsTab.getPanel());
        ApplicationTab aboutTab = new AboutTab();
        mainPanel.addTab(aboutTab.getTabName(), aboutTab.getPanel());

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

    public List<RegexEntity> getGeneralRegexList() {
        return generalRegexList;
    }

    public List<RegexEntity> getExtensionsRegexList() {
        return extensionsRegexList;
    }

    /**
     * Returns the regexScanner instance used for scanning log entries
     */
    public RegexScanner getRegexScanner() {
        return regexScanner;
    }

    /**
     * GetNameExtension return the name of the extension from the configuration file
     */
    public String getNameExtension() {
        return configProperties.getProperty("ui.extension_name");
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
