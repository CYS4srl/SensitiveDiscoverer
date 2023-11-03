/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import burp.ITextEditor;
import com.cys4.sensitivediscoverer.controller.Utils;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static com.cys4.sensitivediscoverer.controller.Messages.getLocaleString;

public class LoggerTab implements ApplicationTab {
    //TODO move these constants to a shared place
    public static final Font TITLE_FONT = new Font("Lucida Grande", Font.BOLD, 14);
    public static final Color ACCENT_COLOR = new Color(255, 102, 51);

    private static final String TAB_NAME = getLocaleString("tab-logger");

    private final MainUI mainUI;
    private final JPanel panel;
    private ITextEditor originalRequestViewer;
    private ITextEditor originalResponseViewer;
    private LogTableEntryUI logTableEntryUI;
    private boolean isAnalysisRunning;
    private Thread analyzeProxyHistoryThread;
    private LogTableEntriesUI logTableEntriesUI;

    public LoggerTab(MainUI mainUI) {
        this.mainUI = mainUI;
        this.isAnalysisRunning = false;
        this.analyzeProxyHistoryThread = null;
        this.panel = this.createPanel();
    }

    public LogTableEntriesUI getLogTableEntriesUI() {
        return logTableEntriesUI;
    }

    private JPanel createPanel() {
        JPanel box;
        JPanel boxCenter;
        JPanel boxHeader;
        JScrollPane scrollPane;

        scrollPane = createLogEntriesTable();

        box = new JPanel();
        box.setLayout(new BorderLayout(0, 0));
        boxHeader = createHeaderBar(scrollPane);
        box.add(boxHeader, BorderLayout.NORTH);
        boxCenter = createCenterBox(scrollPane);
        box.add(boxCenter, BorderLayout.CENTER);

        return box;
    }

    /**
     * Function to call before an analysis start.
     * It performs operations required before an analysis.
     */
    private void preAnalysisOperations() {
        // disable components that shouldn't be used while scanning
        Utils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), false, "analysisDependent");
    }

    /**
     * Function to call after an analysis start.
     * It performs operations required after an analysis.
     */
    private void postAnalysisOperations() {
        // re-enable components not usable while scanning
        Utils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), true, "analysisDependent");
    }

    private JPanel createCenterBox(JScrollPane scrollPane) {
        JPanel responsePanel;
        JPanel requestPanelHeader;
        JPanel requestPanel;
        JSplitPane requestResponseSplitPane;
        JPanel boxCenter;
        JPanel responsePanelHeader;
        JSplitPane verticalSplitPane;

        boxCenter = new JPanel();
        boxCenter.setLayout(new GridBagLayout());
        verticalSplitPane = new JSplitPane();
        verticalSplitPane.setOrientation(0);
        verticalSplitPane.setResizeWeight(0.6);
        GridBagConstraints gbc;
        gbc = createGridConstraints(0, 0, 1.0, 1.0, GridBagConstraints.BOTH);
        boxCenter.add(verticalSplitPane, gbc);
        verticalSplitPane.setLeftComponent(scrollPane);
        requestResponseSplitPane = new JSplitPane();
        requestResponseSplitPane.setPreferredSize(new Dimension(233, 150));
        requestResponseSplitPane.setResizeWeight(0.5);
        verticalSplitPane.setRightComponent(requestResponseSplitPane);
        requestPanel = new JPanel(new BorderLayout(0, 0));
        requestResponseSplitPane.setLeftComponent(requestPanel);
        requestPanelHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        requestPanel.add(requestPanelHeader, BorderLayout.NORTH);
        final JLabel requestLabel = new JLabel(getLocaleString("common-request"));
        requestLabel.setFont(TITLE_FONT);
        requestLabel.setForeground(ACCENT_COLOR);
        requestPanelHeader.add(requestLabel, BorderLayout.NORTH);
        requestPanel.add(this.originalRequestViewer.getComponent(), BorderLayout.CENTER);
        responsePanel = new JPanel(new BorderLayout(0, 0));
        requestResponseSplitPane.setRightComponent(responsePanel);
        responsePanelHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        responsePanel.add(responsePanelHeader, BorderLayout.NORTH);
        final JLabel responseLabel = new JLabel(getLocaleString("common-response"));
        responseLabel.setFont(TITLE_FONT);
        responseLabel.setForeground(ACCENT_COLOR);
        responsePanelHeader.add(responseLabel, BorderLayout.NORTH);
        responsePanel.add(this.originalResponseViewer.getComponent(), BorderLayout.CENTER);
        return boxCenter;
    }

    private JPanel createHeaderBar(JScrollPane scrollPane) {
        JPanel rightSidePanel;
        GridBagConstraints gbc;
        JPanel boxHeader;
        JProgressBar progressBar;
        JButton analysisButton;
        JButton clearLogsButton;
        JPanel leftSidePanel;
        JToggleButton exportLogsButton;

        boxHeader = new JPanel();
        boxHeader.setLayout(new GridBagLayout());

        progressBar = new JProgressBar(0, 1);
        progressBar.setStringPainted(true);
        gbc = createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 10);
        boxHeader.add(progressBar, gbc);

        rightSidePanel = new JPanel();
        rightSidePanel.setLayout(new GridBagLayout());
        rightSidePanel.setPreferredSize(new Dimension(0, 40));
        boxHeader.add(rightSidePanel, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        clearLogsButton = createClearLogsButton(scrollPane);
        gbc = createGridConstraints(0, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        rightSidePanel.add(clearLogsButton, gbc);
        final JPanel spacer1 = new JPanel();
        rightSidePanel.add(spacer1, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));
        exportLogsButton = createExportLogsButton();
        rightSidePanel.add(exportLogsButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));

        leftSidePanel = new JPanel();
        leftSidePanel.setLayout(new GridBagLayout());
        leftSidePanel.setPreferredSize(new Dimension(0, 40));
        boxHeader.add(leftSidePanel, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        analysisButton = createAnalysisButton(progressBar);
        leftSidePanel.add(analysisButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));
        final JPanel spacer2 = new JPanel();
        leftSidePanel.add(spacer2, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));

        return boxHeader;
    }

    private JButton createAnalysisButton(JProgressBar progressBar) {
        JButton analysisButton;
        final String textAnalysisStart = getLocaleString("logger-analysis-start");
        final String textAnalysisStop = getLocaleString("logger-analysis-stop");
        final String textAnalysisStopping = getLocaleString("logger-analysis-stopping");

        analysisButton = new JButton();
        analysisButton.setText(textAnalysisStart);
        analysisButton.addActionListener(actionEvent -> {
            if (!isAnalysisRunning) {
                this.preAnalysisOperations();
                isAnalysisRunning = true;
                analyzeProxyHistoryThread = new Thread(() -> {
                    String previousText = analysisButton.getText();
                    analysisButton.setText(textAnalysisStop);
                    logTableEntryUI.setAutoCreateRowSorter(false);

                    this.mainUI.getBurpLeaksScanner().analyzeProxyHistory(progressBar);

                    analysisButton.setText(previousText);
                    logTableEntryUI.setAutoCreateRowSorter(true);
                    analyzeProxyHistoryThread = null;
                    isAnalysisRunning = false;
                    this.postAnalysisOperations();
                });
                analyzeProxyHistoryThread.start();

                logTableEntryUI.validate();
                logTableEntryUI.repaint();
            } else {
                if (Objects.isNull(analyzeProxyHistoryThread)) return;

                analysisButton.setEnabled(false);
                analysisButton.setText(textAnalysisStopping);
                this.mainUI.getBurpLeaksScanner().setInterruptScan(true);

                new Thread(() -> {
                    try {
                        analyzeProxyHistoryThread.join();
                        this.mainUI.getBurpLeaksScanner().setInterruptScan(false);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    analysisButton.setEnabled(true);
                    analysisButton.setText(textAnalysisStart);
                }).start();
            }
        });
        return analysisButton;
    }

    private JScrollPane createLogEntriesTable() {
        logTableEntriesUI = new LogTableEntriesUI(this.mainUI.getLogEntries());
        this.originalRequestViewer = this.mainUI.getCallbacks().createTextEditor();
        this.originalResponseViewer = this.mainUI.getCallbacks().createTextEditor();
        this.logTableEntryUI = new LogTableEntryUI(logTableEntriesUI, this.mainUI.getLogEntries(), this.originalRequestViewer, this.originalResponseViewer);
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
                        LogEntity logentry = mainUI.getLogEntries().get(realRow);

                        if (e.getComponent() instanceof LogTableEntryUI) {
                            new ContextMenuUI(logentry, mainUI.getLogEntries(), originalRequestViewer, originalResponseViewer, logTableEntriesUI, logTableEntryUI, mainUI.getCallbacks(), isAnalysisRunning)
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

    private JToggleButton createExportLogsButton() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem itemToCSV = new JMenuItem(getLocaleString("common-toCSV"));
        itemToCSV.addActionListener(actionEvent -> {
            java.util.List<String> lines = new ArrayList<>();

            lines.add(String.format("\"%s\",\"%s\",\"%s\"",
                    logTableEntriesUI.getColumnNameFormatted(0),
                    logTableEntriesUI.getColumnNameFormatted(1),
                    logTableEntriesUI.getColumnNameFormatted(3)));

            // values
            for (int i = 0; i < logTableEntriesUI.getRowCount(); i++) {
                String request_id = logTableEntriesUI.getValueAt(i, 0).toString();
                String url = logTableEntriesUI.getValueAt(i, 1).toString();
                String matchEscaped = logTableEntriesUI.getValueAt(i, 3).toString().replaceAll("\"", "\"\"");
                lines.add(String.format("\"%s\",\"%s\",\"%s\"", request_id, url, matchEscaped));
            }

            Utils.saveToFile("csv", lines);
        });
        menu.add(itemToCSV);

        JMenuItem itemToJSON = new JMenuItem(getLocaleString("common-toJSON"));
        itemToJSON.addActionListener(actionEvent -> {
            java.util.List<JsonObject> lines = new ArrayList<>();

            String prop1 = logTableEntriesUI.getColumnNameFormatted(0);
            String prop2 = logTableEntriesUI.getColumnNameFormatted(1);
            String prop3 = logTableEntriesUI.getColumnNameFormatted(3);

            // values
            for (int i = 0; i < logTableEntriesUI.getRowCount(); i++) {
                JsonObject obj = new JsonObject();
                obj.addProperty(prop1, logTableEntriesUI.getValueAt(i, 0).toString());
                obj.addProperty(prop2, logTableEntriesUI.getValueAt(i, 1).toString());
                obj.addProperty(prop3, logTableEntriesUI.getValueAt(i, 3).toString());
                lines.add(obj);
            }

            GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
            Gson gson = builder.create();
            Type tListEntries = new TypeToken<ArrayList<JsonObject>>() {
            }.getType();
            Utils.saveToFile("json", List.of(gson.toJson(lines, tListEntries)));
        });
        menu.add(itemToJSON);

        MenuButton btnExportLogs = new MenuButton(getLocaleString("logger-exportLogs-label"), menu);
        btnExportLogs.putClientProperty("analysisDependent", "1");

        return btnExportLogs;
    }

    private JButton createClearLogsButton(JScrollPane scrollPaneLogger) {
        JButton btnClearLogs = new JButton(getLocaleString("logger-clearLogs-label"));
        btnClearLogs.addActionListener(e -> {
            int dialog = JOptionPane.showConfirmDialog(null, getLocaleString("logger-clearLogs-confirm"));
            if (dialog == JOptionPane.YES_OPTION) {
                mainUI.getLogEntries().clear();
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

    private GridBagConstraints createGridConstraints(int gridx, int gridy, double weightx, double weighty, int fill) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gridx;
        gbc.gridy = gridy;
        gbc.weightx = weightx;
        gbc.weighty = weighty;
        gbc.fill = fill;
        return gbc;
    }

    @Override
    public JPanel getPanel() {
        return this.panel;
    }

    @Override
    public String getTabName() {
        return TAB_NAME;
    }
}
