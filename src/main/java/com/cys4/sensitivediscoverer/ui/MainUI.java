/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.ITextEditor;
import com.cys4.sensitivediscoverer.controller.Utils;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.scanner.BurpLeaksScanner;
import com.cys4.sensitivediscoverer.seed.RegexSeeder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;

import static com.cys4.sensitivediscoverer.controller.Messages.getLocaleString;

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
    // default options
    private Properties _PROPERTIES_PluginProperties;
    // ui components
    private LogTableEntriesUI logTableEntriesUI;
    private LogTableEntryUI logTableEntryUI;
    private JSplitPane splitPane;
    private ITextEditor originalRequestViewer;
    private ITextEditor originalResponseViewer;
    /**
     * Analyze Proxy History
     */
    private Thread analyzeProxyHistoryThread;
    private boolean isAnalysisRunning;
    /**
     * Max response size in bytes. Defaults to 10MB
     */
    private int maxSizeValue = 10_000_000;

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // setup stdout/stderr
        System.setOut(new PrintStream(callbacks.getStdout(), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(callbacks.getStderr(), true, StandardCharsets.UTF_8));

        this.generalRegexList = RegexSeeder.getGeneralRegexes();
        this.extensionsRegexList = RegexSeeder.getExtensionRegexes();

        // Analyze Proxy History
        this.analyzeProxyHistoryThread = null;
        this.isAnalysisRunning = false;

        // Logger elements
        this.logEntries = new ArrayList<>();
        this.burpLeaksScanner = new BurpLeaksScanner(4, this, callbacks, logEntries, this.generalRegexList, this.extensionsRegexList);

        loadConfigFile();
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
        // load the prop files
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("config.properties")) {
            assert (input != null);

            //load a properties file from class path
            _PROPERTIES_PluginProperties = new Properties();
            _PROPERTIES_PluginProperties.load(input);

        } catch (IOException ex) {
            ex.printStackTrace();
        }
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
        return _PROPERTIES_PluginProperties.getProperty("ui.name.extension_name");
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

    /**
     * used by the burp extender to add a new entry
     */
    public void logTableEntriesUIAddNewRow(int row) {
        logTableEntriesUI.addNewRow(row);
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    /**
     * Main function which initializes the extension and creates the UI
     */
    public void initialize() {
        // Updates the UI in async method
        SwingUtilities.invokeLater(this::_initialize);
    }

    private void _initialize() {
        JTabbedPane tabbedPane = new JTabbedPane();

        //TODO convert to ApplicationTab
        tabbedPane.addTab(getLocaleString("tab-logger"), createLoggerPanel());

        ApplicationTab optionsTab = new OptionsTab(this);
        callbacks.customizeUiComponent(optionsTab.getPanel());
        tabbedPane.addTab(getLocaleString("tab-options"), optionsTab.getPanel());

        ApplicationTab aboutTab = new AboutTab();
        callbacks.customizeUiComponent(aboutTab.getPanel());
        tabbedPane.addTab(getLocaleString("tab-about"), aboutTab.getPanel());

        // main panel
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.add(tabbedPane);
        callbacks.customizeUiComponent(splitPane);

        // add the custom tab to Burp's UI
        callbacks.addSuiteTab(MainUI.this);
    }

    private JPanel createLoggerPanel() {
        JPanel tabPanelLogger = new JPanel();
        tabPanelLogger.setLayout(new BorderLayout());

        JScrollPane scrollPaneLogger = setupLogger_LogTable();

        // panel that contains the buttonsPanel and the loggerPane
        JPanel buttonsLoggerPanel = createLogger_ButtonPanel(tabPanelLogger, scrollPaneLogger);

        // Request / Response viewers under the logger
        JSplitPane requestResponseSplitPane = createLogger_RequestResponse();

        // panel that contains all the graphical elements in the Logger Panel
        JSplitPane mainLoggerPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buttonsLoggerPanel, requestResponseSplitPane);
        tabPanelLogger.add(mainLoggerPanel);

        callbacks.customizeUiComponent(logTableEntryUI);
        callbacks.customizeUiComponent(mainLoggerPanel);
        callbacks.customizeUiComponent(scrollPaneLogger);
        callbacks.customizeUiComponent(requestResponseSplitPane);

        return tabPanelLogger;
    }

    /**
     * Panel that contains the buttonsPanel and the loggerPane
     *
     * @param tabPanelLogger   Panel where everything is rendered.
     * @param scrollPaneLogger Scroll pane where log entries are saved.
     */
    private JPanel createLogger_ButtonPanel(JPanel tabPanelLogger, JScrollPane scrollPaneLogger) {
        JPanel buttonPanelLog = new JPanel();
        buttonPanelLog.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);

        createLogger_AnalyzeHTTPHistory(tabPanelLogger)
                .forEach((component) -> buttonPanelLog.add(component, BorderLayout.NORTH));

        JButton clearLogsBtn = createLogger_ClearLogs(scrollPaneLogger);
        buttonPanelLog.add(clearLogsBtn, BorderLayout.NORTH);
        JToggleButton exportLogsBtn = createLogger_ExportLogs();
        buttonPanelLog.add(exportLogsBtn, BorderLayout.NORTH);

        JPanel buttonsLoggerPanel = new JPanel();
        buttonsLoggerPanel.setLayout(new BoxLayout(buttonsLoggerPanel, BoxLayout.Y_AXIS));
        buttonsLoggerPanel.setLayout(new BorderLayout());
        buttonsLoggerPanel.add(buttonPanelLog, BorderLayout.NORTH);
        buttonsLoggerPanel.add(scrollPaneLogger, BorderLayout.CENTER);

        return buttonsLoggerPanel;
    }

    private JScrollPane setupLogger_LogTable() {
        logTableEntriesUI = new LogTableEntriesUI(this.logEntries);
        originalRequestViewer = this.callbacks.createTextEditor();
        originalResponseViewer = this.callbacks.createTextEditor();
        logTableEntryUI = new LogTableEntryUI(logTableEntriesUI, this.logEntries, this.originalRequestViewer, this.originalResponseViewer);
        // disable sorting on columns while scanning. This helps to prevent Swing exceptions.
        logTableEntryUI.getTableHeader().putClientProperty("analysisDependent", "1");

        // when you right-click on a logTable entry, it will appear a context menu defined here
        MouseAdapter contextMenu = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                onMouseEvent(e);
            }

            private void onMouseEvent(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = logTableEntryUI.getSelectedRow();
                    if (row == -1) return;
                    logTableEntryUI.setRowSelectionInterval(row, row);
                    if (logTableEntryUI.getSelectedRowCount() == 1) {
                        int realRow = logTableEntryUI.convertRowIndexToModel(row);
                        LogEntity logentry = logEntries.get(realRow);

                        if (e.getComponent() instanceof LogTableEntryUI) {
                            new ContextMenuUI(logentry, logEntries, originalRequestViewer, originalResponseViewer, logTableEntriesUI, logTableEntryUI, callbacks, isAnalysisRunning)
                                    .show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                }
            }
        };
        logTableEntryUI.addMouseListener(contextMenu);

        ListSelectionModel listSelectionModel = logTableEntryUI.getSelectionModel();
        logTableEntryUI.setSelectionModel(listSelectionModel);

        return new JScrollPane(logTableEntryUI);
    }

    private JSplitPane createLogger_RequestResponse() {
        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        requestResponseSplitPane.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        JPanel requestResponsePanel = new JPanel();
        requestResponsePanel.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        requestResponsePanel.add(requestResponseSplitPane);

        JPanel originalRequestPanel = new JPanel();
        JLabel originalRequestLabel = new JLabel(getLocaleString("common-request"));
        originalRequestLabel.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
        originalRequestLabel.setForeground(new Color(255, 102, 51));
        originalRequestPanel.add(originalRequestLabel);
        originalRequestPanel.add(originalRequestViewer.getComponent());

        JPanel originalResponsePanel = new JPanel();
        JLabel originalResponseLabel = new JLabel(getLocaleString("common-response"));
        originalResponseLabel.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
        originalResponseLabel.setForeground(new Color(255, 102, 51));
        originalResponsePanel.add(originalResponseLabel);
        originalResponsePanel.add(originalResponseViewer.getComponent());

        originalRequestPanel.setLayout(new BoxLayout(originalRequestPanel, BoxLayout.PAGE_AXIS));
        originalResponsePanel.setLayout(new BoxLayout(originalResponsePanel, BoxLayout.PAGE_AXIS));

        requestResponseSplitPane.setLeftComponent(originalRequestPanel);
        requestResponseSplitPane.setRightComponent(originalResponsePanel);
        requestResponseSplitPane.setResizeWeight(0.50);
        requestResponseSplitPane.setMaximumSize(new Dimension(2000, 500));

        return requestResponseSplitPane;
    }

    private JButton createLogger_ClearLogs(JScrollPane scrollPaneLogger) {
        JButton btnClearLogs = new JButton(getLocaleString("logger-clearLogs-label"));
        btnClearLogs.addActionListener(e -> {
            int dialog = JOptionPane.showConfirmDialog(null, getLocaleString("logger-clearLogs-confirm"));
            if (dialog == JOptionPane.YES_OPTION) {
                logEntries.clear();
                logTableEntriesUI.clear();

                originalResponseViewer.setText(new byte[0]);
                originalResponseViewer.setSearchExpression("");
                originalRequestViewer.setText(new byte[0]);
            }

            scrollPaneLogger.validate();
            scrollPaneLogger.repaint();
        });

        btnClearLogs.putClientProperty("analysisDependent", "1");
        return btnClearLogs;
    }

    /**
     * Export logs menu, to export the log entries to file
     *
     * @return JToggleButton for log export popup
     */
    private JToggleButton createLogger_ExportLogs() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem itemToCSV = new JMenuItem(getLocaleString("common-toCSV"));
        itemToCSV.addActionListener(actionEvent -> {
            List<String> lines = new ArrayList<>();

            lines.add(String.format("\"%s\",\"%s\",\"%s\"",
                    this.logTableEntriesUI.getColumnNameFormatted(0),
                    this.logTableEntriesUI.getColumnNameFormatted(1),
                    this.logTableEntriesUI.getColumnNameFormatted(3)));

            // values
            for (int i = 0; i < this.logTableEntriesUI.getRowCount(); i++) {
                String request_id = this.logTableEntriesUI.getValueAt(i, 0).toString();
                String url = this.logTableEntriesUI.getValueAt(i, 1).toString();
                String matchEscaped = this.logTableEntriesUI.getValueAt(i, 3).toString().replaceAll("\"", "\"\"");
                lines.add(String.format("\"%s\",\"%s\",\"%s\"", request_id, url, matchEscaped));
            }

            Utils.saveToFile("csv", lines);
        });
        menu.add(itemToCSV);

        JMenuItem itemToJSON = new JMenuItem(getLocaleString("common-toJSON"));
        itemToJSON.addActionListener(actionEvent -> {
            List<JsonObject> lines = new ArrayList<>();

            String prop1 = this.logTableEntriesUI.getColumnNameFormatted(0);
            String prop2 = this.logTableEntriesUI.getColumnNameFormatted(1);
            String prop3 = this.logTableEntriesUI.getColumnNameFormatted(3);

            // values
            for (int i = 0; i < this.logTableEntriesUI.getRowCount(); i++) {
                JsonObject obj = new JsonObject();
                obj.addProperty(prop1, this.logTableEntriesUI.getValueAt(i, 0).toString());
                obj.addProperty(prop2, this.logTableEntriesUI.getValueAt(i, 1).toString());
                obj.addProperty(prop3, this.logTableEntriesUI.getValueAt(i, 3).toString());
                lines.add(obj);
            }

            GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
            Gson gson = builder.create();
            Type tListEntries = new TypeToken<ArrayList<JsonObject>>() {}.getType();
            Utils.saveToFile("json", List.of(gson.toJson(lines, tListEntries)));
        });
        menu.add(itemToJSON);

        MenuButton btnExportLogs = new MenuButton(getLocaleString("logger-exportLogs-label"), menu);
        btnExportLogs.putClientProperty("analysisDependent", "1");

        return btnExportLogs;
    }

    /**
     * Function to call before an analysis start.
     * It performs operations required before an analysis.
     */
    private void preAnalysisOperations() {
        // disable components that shouldn't be used while scanning
        Utils.setEnabledRecursiveComponentsWithProperty(this.getSplitPane(), false, "analysisDependent");
    }

    /**
     * Function to call after an analysis start.
     * It performs operations required after an analysis.
     */
    private void postAnalysisOperations() {
        // re-enable components not usable while scanning
        Utils.setEnabledRecursiveComponentsWithProperty(this.getSplitPane(), true, "analysisDependent");
    }

    private List<JComponent> createLogger_AnalyzeHTTPHistory(JPanel tabPanelLogger) {
        final String textAnalysisStart = getLocaleString("logger-analysis-start");
        final String textAnalysisStop = getLocaleString("logger-analysis-stop");
        final String textAnalysisStopping = getLocaleString("logger-analysis-stopping");

        JButton btnAnalysis = new JButton(textAnalysisStart);
        JProgressBar progressBar = new JProgressBar(0, 1);

        btnAnalysis.addActionListener(actionEvent -> {
            if (!isAnalysisRunning) {
                preAnalysisOperations();
                this.isAnalysisRunning = true;
                this.analyzeProxyHistoryThread = new Thread(() -> {
                    String previousText = btnAnalysis.getText();
                    btnAnalysis.setText(textAnalysisStop);
                    logTableEntryUI.setAutoCreateRowSorter(false);

                    burpLeaksScanner.analyzeProxyHistory(progressBar);

                    btnAnalysis.setText(previousText);
                    logTableEntryUI.setAutoCreateRowSorter(true);
                    this.analyzeProxyHistoryThread = null;
                    this.isAnalysisRunning = false;
                    postAnalysisOperations();
                });
                this.analyzeProxyHistoryThread.start();

                logTableEntryUI.validate();
                logTableEntryUI.repaint();
            } else {
                if (Objects.isNull(this.analyzeProxyHistoryThread)) return;

                btnAnalysis.setEnabled(false);
                btnAnalysis.setText(textAnalysisStopping);
                burpLeaksScanner.setInterruptScan(true);

                new Thread(() -> {
                    try {
                        this.analyzeProxyHistoryThread.join();
                        burpLeaksScanner.setInterruptScan(false);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    btnAnalysis.setEnabled(true);
                    btnAnalysis.setText(textAnalysisStart);
                }).start();
            }

            tabPanelLogger.validate();
            tabPanelLogger.repaint();
        });

        return Arrays.asList(btnAnalysis, progressBar);
    }

    @Override
    public String getTabCaption() {
        return getNameExtension();
    }

    @Override
    public Component getUiComponent() {
        return getSplitPane();
    }
}
