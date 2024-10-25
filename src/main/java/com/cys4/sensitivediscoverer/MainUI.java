package com.cys4.sensitivediscoverer;

import burp.api.montoya.MontoyaApi;
import com.cys4.sensitivediscoverer.model.RegexScannerOptions;
import com.cys4.sensitivediscoverer.ui.tab.AboutTab;
import com.cys4.sensitivediscoverer.ui.tab.ApplicationTab;
import com.cys4.sensitivediscoverer.ui.tab.LoggerTab;
import com.cys4.sensitivediscoverer.ui.tab.OptionsTab;
import com.cys4.sensitivediscoverer.utils.SwingUtils;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Font;
import java.util.Properties;

import static com.cys4.sensitivediscoverer.utils.Utils.loadConfigFile;

public class MainUI {
    private final MontoyaApi burpApi;
    private final Properties configProperties;
    private final RegexScannerOptions scannerOptions;
    private JTabbedPane mainPanel;
    private boolean interfaceInitialized;

    public MainUI(MontoyaApi burpApi) throws Exception {
        this.interfaceInitialized = false;
        this.burpApi = burpApi;
        this.configProperties = loadConfigFile();
        this.scannerOptions = new RegexScannerOptions(this.configProperties, this.burpApi.persistence().preferences());
    }

    public boolean isInterfaceInitialized() {
        return interfaceInitialized;
    }

    public RegexScannerOptions getScannerOptions() {
        return scannerOptions;
    }

    /**
     * Main function that initializes the extension and creates the UI, asynchronously
     */
    public void initializeUI() {
        SwingUtilities.invokeLater(this::_initializeUI);
    }

    /**
     * UI initialization logic that must run in the EDT
     */
    private void _initializeUI() {
        SwingUtils.assertIsEDT();

        mainPanel = new JTabbedPane();
        LoggerTab loggerTab = new LoggerTab(this);
        mainPanel.addTab(loggerTab.getTabName(), loggerTab.getPanel());
        ApplicationTab optionsTab = new OptionsTab(this.getScannerOptions());
        mainPanel.addTab(optionsTab.getTabName(), optionsTab.getPanel());
        ApplicationTab aboutTab = new AboutTab();
        mainPanel.addTab(aboutTab.getTabName(), aboutTab.getPanel());

        burpApi.userInterface().applyThemeToComponent(mainPanel);
        burpApi.userInterface().registerSuiteTab(this.getExtensionName(), this.getMainPanel());

        this.interfaceInitialized = true;
    }

    /**
     * Returns the extension's main panel
     */
    public JTabbedPane getMainPanel() {
        return mainPanel;
    }

    public MontoyaApi getBurpApi() {
        return burpApi;
    }

    /**
     * getExtensionName return the name of the extension from the configuration file
     */
    public String getExtensionName() {
        return configProperties.getProperty("ui.extension_name");
    }

    public static final class UIOptions {
        public static final Font H1_FONT = new Font("SansSerif", Font.BOLD, 16);
        public static final Font H2_FONT = new Font("SansSerif", Font.BOLD, 14);
        public static final Color ACCENT_COLOR = new Color(255, 102, 51);
    }
}
