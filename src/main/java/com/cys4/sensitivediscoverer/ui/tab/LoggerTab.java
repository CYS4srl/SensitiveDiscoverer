package com.cys4.sensitivediscoverer.ui.tab;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.RegexScanner;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogsTableModel;
import com.cys4.sensitivediscoverer.ui.LogsTable;
import com.cys4.sensitivediscoverer.ui.LogsTableContextMenu;
import com.cys4.sensitivediscoverer.ui.PopupMenuButton;
import com.cys4.sensitivediscoverer.utils.FileUtils;
import com.cys4.sensitivediscoverer.utils.LoggerUtils;
import com.cys4.sensitivediscoverer.utils.SwingUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class LoggerTab implements ApplicationTab {
    private static final String TAB_NAME = getLocaleString("tab-logger");

    private final MainUI mainUI;
    private final JPanel panel;
    /**
     * List containing the findings history (log entries).
     * <br><br>
     * When running multiple analysis on the same RegexScanner instance,
     * this list remains the same unless manually cleared.
     * This is required for not logging the same finding twice.
     */
    private final List<LogEntity> logEntries;
    private final Object analyzeLock = new Object();
    private final Object loggerLock = new Object();
    private final RegexScanner regexScanner;
    private HttpRequestEditor originalRequestViewer;
    private HttpResponseEditor originalResponseViewer;
    private LogsTableModel logsTableModel;
    private LogsTable logsTable;
    private TableRowSorter<LogsTableModel> logsTableRowSorter;
    private boolean isAnalysisRunning;
    private Thread analyzeProxyHistoryThread;
    /**
     * Counter of analyzed items. Used mainly for the progress bar
     */
    private int analyzedItems = 0;

    public LoggerTab(MainUI mainUI) {
        this.mainUI = mainUI;
        this.isAnalysisRunning = false;
        this.analyzeProxyHistoryThread = null;
        this.logEntries = new ArrayList<>();
        this.regexScanner = new RegexScanner(
                this.mainUI.getBurpApi(),
                this.mainUI.getScannerOptions(),
                mainUI.getGeneralRegexList(),
                mainUI.getExtensionsRegexList());

        // keep as last call
        this.panel = this.createPanel();
    }

    private JPanel createPanel() {
        JPanel box;
        JPanel boxCenter;
        JPanel boxHeader;
        JScrollPane logEntriesPane;

        logEntriesPane = createLogEntriesTable();

        box = new JPanel();
        box.setLayout(new BorderLayout(0, 0));
        boxHeader = createHeaderBar(logEntriesPane);
        box.add(boxHeader, BorderLayout.NORTH);
        boxCenter = createCenterBox(logEntriesPane);
        box.add(boxCenter, BorderLayout.CENTER);

        return box;
    }

    /**
     * Function to call before an analysis start.
     * It performs operations required before an analysis.
     */
    private void preAnalysisOperations() {
        // disable components that shouldn't be used while scanning
        SwingUtils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), false, "analysisDependent");
    }

    /**
     * Function to call after an analysis start.
     * It performs operations required after an analysis.
     */
    private void postAnalysisOperations() {
        // re-enable components not usable while scanning
        SwingUtils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), true, "analysisDependent");
    }

    private JPanel createCenterBox(JScrollPane logEntriesPane) {
        JPanel boxCenter;
        JPanel responsePanel;
        JPanel requestPanelHeader;
        JPanel requestPanel;
        JPanel responsePanelHeader;
        GridBagConstraints gbc;

        boxCenter = new JPanel();
        boxCenter.setLayout(new GridBagLayout());

        // vertical split plane - log entries on top and req/res editor on bottom
        JSplitPane verticalSplitPane = new JSplitPane();
        verticalSplitPane.setOrientation(0);
        verticalSplitPane.setResizeWeight(0.6);
        gbc = createGridConstraints(0, 0, 1.0, 1.0, GridBagConstraints.BOTH);
        boxCenter.add(verticalSplitPane, gbc);
        verticalSplitPane.setLeftComponent(logEntriesPane);
        JSplitPane requestResponseSplitPane = new JSplitPane();
        requestResponseSplitPane.setPreferredSize(new Dimension(233, 150));
        requestResponseSplitPane.setResizeWeight(0.5);
        verticalSplitPane.setRightComponent(requestResponseSplitPane);

        // request panel
        requestPanel = new JPanel(new BorderLayout(0, 0));
        requestResponseSplitPane.setLeftComponent(requestPanel);
        requestPanelHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        requestPanel.add(requestPanelHeader, BorderLayout.NORTH);
        final JLabel requestLabel = new JLabel(getLocaleString("common-request"));
        requestLabel.setFont(MainUI.UIOptions.H2_FONT);
        requestLabel.setForeground(MainUI.UIOptions.ACCENT_COLOR);
        requestPanelHeader.add(requestLabel, BorderLayout.NORTH);
        requestPanel.add(this.originalRequestViewer.uiComponent(), BorderLayout.CENTER);
        responsePanel = new JPanel(new BorderLayout(0, 0));
        requestResponseSplitPane.setRightComponent(responsePanel);

        // response panel
        responsePanelHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        responsePanel.add(responsePanelHeader, BorderLayout.NORTH);
        final JLabel responseLabel = new JLabel(getLocaleString("common-response"));
        responseLabel.setFont(MainUI.UIOptions.H2_FONT);
        responseLabel.setForeground(MainUI.UIOptions.ACCENT_COLOR);
        responsePanelHeader.add(responseLabel, BorderLayout.NORTH);
        responsePanel.add(this.originalResponseViewer.uiComponent(), BorderLayout.CENTER);

        return boxCenter;
    }

    private JPanel createHeaderBar(JScrollPane logEntriesPane) {
        JPanel rightSidePanel;
        JPanel boxHeader;
        JPanel leftSidePanel;
        JPanel searchBarPanel;
        GridBagConstraints gbc;

        boxHeader = new JPanel();
        boxHeader.setLayout(new GridBagLayout());

        JProgressBar progressBar = new JProgressBar(0, 1);
        progressBar.setStringPainted(true);
        gbc = createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 10);
        boxHeader.add(progressBar, gbc);

        leftSidePanel = new JPanel();
        leftSidePanel.setLayout(new GridBagLayout());
        leftSidePanel.setPreferredSize(new Dimension(0, 40));
        boxHeader.add(leftSidePanel, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        JButton analysisButton = createAnalysisButton(progressBar);
        leftSidePanel.add(analysisButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));
        final JPanel spacer2 = new JPanel();
        leftSidePanel.add(spacer2, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));

        rightSidePanel = new JPanel();
        rightSidePanel.setLayout(new GridBagLayout());
        rightSidePanel.setPreferredSize(new Dimension(0, 40));
        boxHeader.add(rightSidePanel, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        JButton clearLogsButton = createClearLogsButton(logEntriesPane);
        gbc = createGridConstraints(0, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        rightSidePanel.add(clearLogsButton, gbc);
        final JPanel spacer1 = new JPanel();
        rightSidePanel.add(spacer1, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));
        JToggleButton exportLogsButton = createExportLogsButton();
        rightSidePanel.add(exportLogsButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));

        searchBarPanel = new JPanel();
        searchBarPanel.setLayout(new GridBagLayout());
        gbc = createGridConstraints(0, 1, 1.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(2, 10, 5, 10);
        gbc.gridwidth = 3;
        boxHeader.add(searchBarPanel, gbc);
        JLabel searchLabel = new JLabel(getLocaleString("logger-searchBar-label"));
        gbc = createGridConstraints(0, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        searchBarPanel.add(searchLabel, gbc);

        JTextField searchField = new JTextField();
        gbc = createGridConstraints(1, 0, 1, 0, GridBagConstraints.HORIZONTAL);
        searchBarPanel.add(searchField, gbc);

        JCheckBox regexCheckBox = new JCheckBox();
        regexCheckBox.setText("Regex");
        regexCheckBox.setSelected(true);
        gbc = createGridConstraints(2, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        searchBarPanel.add(regexCheckBox, gbc);

        JCheckBox matchCheckBox = new JCheckBox();
        matchCheckBox.setText("Match");
        matchCheckBox.setSelected(true);
        gbc = createGridConstraints(3, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        searchBarPanel.add(matchCheckBox, gbc);

        JCheckBox URLCheckBox = new JCheckBox();
        URLCheckBox.setText("URL");
        URLCheckBox.setSelected(true);
        gbc = createGridConstraints(4, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        searchBarPanel.add(URLCheckBox, gbc);

        ActionListener checkBoxListener = e -> {
            updateRowFilter(searchField.getText(), regexCheckBox.isSelected(), matchCheckBox.isSelected(), URLCheckBox.isSelected());
        };
        regexCheckBox.addActionListener(checkBoxListener);
        matchCheckBox.addActionListener(checkBoxListener);
        URLCheckBox.addActionListener(checkBoxListener);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {
                updateRowFilter(searchField.getText(), regexCheckBox.isSelected(), matchCheckBox.isSelected(), URLCheckBox.isSelected());
            }

            @Override
            public void removeUpdate(DocumentEvent documentEvent) {
                updateRowFilter(searchField.getText(), regexCheckBox.isSelected(), matchCheckBox.isSelected(), URLCheckBox.isSelected());
            }

            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                updateRowFilter(searchField.getText(), regexCheckBox.isSelected(), matchCheckBox.isSelected(), URLCheckBox.isSelected());
            }
        });

        return boxHeader;
    }

    /**
     * Filter rows of LogsTable that contains text string
     *
     * @param text To search
     * @param includeRegex To search also in Regex column
     * @param includeMatch To search also in Match column
     * @param includeURL To search also in URL column
     */
    private void updateRowFilter(String text, boolean includeRegex, boolean includeMatch, boolean includeURL) {
        if (text.isBlank()) {
            logsTableRowSorter.setRowFilter(null);
        } else {
            logsTableRowSorter.setRowFilter(new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends LogsTableModel, ? extends Integer> entry) {
                    List<LogsTableModel.Column> places = new ArrayList<>(List.of());
                    if (includeRegex) places.add(LogsTableModel.Column.REGEX);
                    if (includeMatch) places.add(LogsTableModel.Column.MATCH);
                    if (includeURL) places.add(LogsTableModel.Column.URL);
                    return places.stream().anyMatch(column -> entry.getStringValue(column.getIndex()).toLowerCase().contains(text.toLowerCase()));
                }
            });
        }
    }

    /**
     * Creates a button that handles the analysis of the burp's http history
     *
     * @param progressBar the progress bar to update with the analysis status
     * @return the analysis button
     */
    private JButton createAnalysisButton(JProgressBar progressBar) {
        JButton analysisButton = new JButton();
        String startAnalysisText = getLocaleString("logger-analysis-start");
        analysisButton.putClientProperty("initialText", startAnalysisText);
        analysisButton.setText(startAnalysisText);
        analysisButton.addActionListener(actionEvent -> {
            if (!isAnalysisRunning) {
                startAnalysisAction(progressBar, analysisButton);
            } else {
                stopAnalysisAction(analysisButton);
            }
        });
        return analysisButton;
    }

    private void stopAnalysisAction(JButton analysisButton) {
        if (Objects.isNull(analyzeProxyHistoryThread)) return;

        analysisButton.setEnabled(false);
        analysisButton.setText(getLocaleString("logger-analysis-stopping"));
        regexScanner.setInterruptScan(true);

        new Thread(() -> {
            try {
                analyzeProxyHistoryThread.join();
                regexScanner.setInterruptScan(false);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            analysisButton.setEnabled(true);
            analysisButton.setText(getLocaleString("logger-analysis-start"));
        }).start();
    }

    private void startAnalysisAction(JProgressBar progressBar, JButton analysisButton) {
        this.preAnalysisOperations();
        isAnalysisRunning = true;
        analyzeProxyHistoryThread = new Thread(new Runnable() {
            @Override
            public void run() {
                setupScan();
                startScan();
                finalizeScan();
            }

            private Runnable setupProgressBarCallback(int maxItems) {
                progressBar.setMaximum(maxItems);
                return () -> {
                    synchronized (analyzeLock) {
                        LoggerTab.this.analyzedItems++;
                    }
                    progressBar.setValue(LoggerTab.this.analyzedItems);
                };
            }

            private void setupScan() {
                analysisButton.setText(getLocaleString("logger-analysis-stop"));
//todo                logsTable.setAutoCreateRowSorter(false);
                LoggerTab.this.analyzedItems = 0;
                progressBar.setValue(LoggerTab.this.analyzedItems);
            }

            private void startScan() {
                Consumer<LogEntity> addLogEntryCallback = LoggerUtils.createAddLogEntryCallback(logEntries, loggerLock, Optional.of(logsTableModel));
                regexScanner.analyzeProxyHistory(this::setupProgressBarCallback, addLogEntryCallback);
            }

            private void finalizeScan() {
                analysisButton.setText((String) analysisButton.getClientProperty("initialText"));
//todo                logsTable.setAutoCreateRowSorter(true);
                analyzeProxyHistoryThread = null;
                isAnalysisRunning = false;
                LoggerTab.this.postAnalysisOperations();
            }
        });
        analyzeProxyHistoryThread.start();

        logsTable.validate();
        logsTable.repaint();
    }

    private JScrollPane createLogEntriesTable() {
        logsTableModel = new LogsTableModel(logEntries);
        this.originalRequestViewer = this.mainUI.getBurpApi().userInterface().createHttpRequestEditor();
        this.originalResponseViewer = this.mainUI.getBurpApi().userInterface().createHttpResponseEditor();
        this.logsTable = new LogsTable(logsTableModel, logEntries, this.originalRequestViewer, this.originalResponseViewer);
        // disable sorting on columns while scanning. This helps to prevent Swing exceptions.
        logsTable.getTableHeader().putClientProperty("analysisDependent", "1");
        logsTable.setAutoCreateRowSorter(false);
        logsTableRowSorter = new TableRowSorter<>(logsTableModel);
        logsTable.setRowSorter(logsTableRowSorter);

        // when you right-click on a logTable entry, it will appear a context menu defined here
        MouseAdapter contextMenu = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                onMouseEvent(e);
            }

            private void onMouseEvent(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = logsTable.getSelectedRow();
                    if (row == -1) return;
                    int realRow = logsTable.convertRowIndexToModel(row);
                    LogEntity logEntry = logEntries.get(realRow);

                    if (e.getComponent() instanceof LogsTable) {
                        new LogsTableContextMenu(logEntry, logEntries, originalRequestViewer, originalResponseViewer, logsTableModel, logsTable, mainUI.getBurpApi(), isAnalysisRunning)
                                .show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        };
        logsTable.addMouseListener(contextMenu);

        ListSelectionModel listSelectionModel = logsTable.getSelectionModel();
        logsTable.setSelectionModel(listSelectionModel);

        return new JScrollPane(logsTable);
    }

    private JToggleButton createExportLogsButton() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem itemToCSV = new JMenuItem(getLocaleString("common-toCSV"));
        itemToCSV.addActionListener(actionEvent -> {
            String csvFile = SwingUtils.selectFile(List.of("CSV"), false);
            if (csvFile.isBlank()) return;

            java.util.List<String> lines = new ArrayList<>();

            lines.add(String.format("\"%s\",\"%s\",\"%s\"",
                    LogsTableModel.Column.URL.getNameFormatted(),
                    LogsTableModel.Column.REGEX.getNameFormatted(),
                    LogsTableModel.Column.MATCH.getNameFormatted()));

            for (int i = 0; i < logsTable.getRowCount(); i++) {
                String url = logsTableModel.getValueAt(logsTable.convertRowIndexToModel(i), LogsTableModel.Column.URL.getIndex()).toString();
                String description = logsTableModel.getValueAt(logsTable.convertRowIndexToModel(i), LogsTableModel.Column.REGEX.getIndex()).toString();
                String matchEscaped = logsTableModel.getValueAt(logsTable.convertRowIndexToModel(i), LogsTableModel.Column.MATCH.getIndex()).toString().replaceAll("\"", "\"\"");
                lines.add(String.format("\"%s\",\"%s\",\"%s\"", url, description, matchEscaped));
            }

            FileUtils.writeLinesToFile(csvFile, lines);
        });
        menu.add(itemToCSV);

        JMenuItem itemToJSON = new JMenuItem(getLocaleString("common-toJSON"));
        itemToJSON.addActionListener(actionEvent -> {
            String jsonFile = SwingUtils.selectFile(List.of("JSON"), false);
            if (jsonFile.isBlank()) return;

            List<LogsTableModel.Column> fields = List.of(LogsTableModel.Column.URL, LogsTableModel.Column.REGEX, LogsTableModel.Column.MATCH);
            List<JsonObject> lines = IntStream
                    .range(0, logsTableModel.getRowCount())
                    .mapToObj(rowIndex -> {
                        JsonObject json = new JsonObject();
                        fields.forEach(column -> {
                            json.addProperty(column.getNameFormatted(), logsTableModel.getValueAt(rowIndex, column.getIndex()).toString());
                        });
                        return json;
                    }).collect(Collectors.toList());

            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            Type tListEntries = new TypeToken<ArrayList<JsonObject>>() {
            }.getType();

            FileUtils.writeLinesToFile(jsonFile, List.of(gson.toJson(lines, tListEntries)));
        });
        menu.add(itemToJSON);

        PopupMenuButton btnExportLogs = new PopupMenuButton(getLocaleString("logger-exportLogs-label"), menu);
        btnExportLogs.putClientProperty("analysisDependent", "1");

        return btnExportLogs;
    }

    private JButton createClearLogsButton(JScrollPane scrollPaneLogger) {
        JButton btnClearLogs = new JButton(getLocaleString("logger-clearLogs-label"));
        btnClearLogs.addActionListener(e -> {
            int dialog = JOptionPane.showConfirmDialog(null, getLocaleString("logger-clearLogs-confirm"));
            if (dialog == JOptionPane.YES_OPTION) {
                logEntries.clear();
                logsTableModel.clear();

                originalResponseViewer.setResponse(HttpResponse.httpResponse(""));
                originalResponseViewer.setSearchExpression("");
                originalRequestViewer.setRequest(HttpRequest.httpRequest(""));
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
