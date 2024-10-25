package com.cys4.sensitivediscoverer.ui.tab;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.RegexScanner;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogEntriesManager;
import com.cys4.sensitivediscoverer.ui.LogsTableContextMenu;
import com.cys4.sensitivediscoverer.ui.PopupMenuButton;
import com.cys4.sensitivediscoverer.ui.table.LogsTable;
import com.cys4.sensitivediscoverer.ui.table.LogsTableModel;
import com.cys4.sensitivediscoverer.utils.FileUtils;
import com.cys4.sensitivediscoverer.utils.LoggerUtils;
import com.cys4.sensitivediscoverer.utils.SwingUtils;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;
import static com.cys4.sensitivediscoverer.utils.Utils.createGsonBuilder;

public class LoggerTab implements ApplicationTab {
    private static final String TAB_NAME = getLocaleString("tab-logger");

    private final MainUI mainUI;
    private final JPanel panel;
    /**
     * Manager for the list containing the findings history (log entries).
     * <br><br>
     * When running multiple analysis on the same RegexScanner instance,
     * this list remains the same unless manually cleared.
     * This is required for not logging the same finding twice.
     */
    private final LogEntriesManager logEntriesManager;
    private final Object loggerLock = new Object();
    private final RegexScanner regexScanner;
    private HttpRequestEditor originalRequestViewer;
    private HttpResponseEditor originalResponseViewer;
    private LogsTableModel logsTableModel;
    private LogsTable logsTable;
    private TableRowSorter<LogsTableModel> logsTableRowSorter;
    private boolean isAnalysisRunning;
    private Thread analyzeProxyHistoryThread;

    public LoggerTab(MainUI mainUI) {
        this.mainUI = mainUI;
        this.isAnalysisRunning = false;
        this.analyzeProxyHistoryThread = null;
        this.logEntriesManager = new LogEntriesManager();
        this.regexScanner = new RegexScanner(
                this.mainUI.getBurpApi(),
                this.mainUI.getScannerOptions());

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
        boxHeader = createHeaderBox(logEntriesPane);
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
        SwingUtilities.invokeLater(() -> SwingUtils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), false, "analysisDependent"));
        // save current scan options
        this.mainUI.getScannerOptions().saveToPersistentStorage();
    }

    /**
     * Function to call after an analysis start.
     * It performs operations required after an analysis.
     */
    private void postAnalysisOperations() {
        // re-enable components not usable while scanning
        SwingUtilities.invokeLater(() -> SwingUtils.setEnabledRecursiveComponentsWithProperty(this.mainUI.getMainPanel(), true, "analysisDependent"));
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

    private JPanel createHeaderBox(JScrollPane logEntriesPane) {
        JPanel headerBox;
        JPanel analysisBar;
        JPanel resultsFilterBar;
        GridBagConstraints gbc;

        headerBox = new JPanel();
        headerBox.setLayout(new GridBagLayout());

        analysisBar = createAnalysisBar(logEntriesPane);
        gbc = createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL);
        headerBox.add(analysisBar, gbc);

        resultsFilterBar = createResultsFilterBar();
        gbc = createGridConstraints(0, 1, 1.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(2, 10, 5, 10);
        headerBox.add(resultsFilterBar, gbc);

        return headerBox;
    }

    private JPanel createResultsFilterBar() {
        JPanel resultsFilterBar;
        GridBagConstraints gbc;

        resultsFilterBar = new JPanel();
        resultsFilterBar.setLayout(new GridBagLayout());

        JLabel resultsCountLabel = new JLabel(getLocaleString("logger-resultsCount-label"));
        gbc = createGridConstraints(0, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        resultsFilterBar.add(resultsCountLabel, gbc);
        JLabel filteredCountValueLabel = new JLabel("0");
        gbc = createGridConstraints(1, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        logsTableRowSorter.addRowSorterListener(rowSorterEvent -> SwingUtilities.invokeLater(() -> {
            filteredCountValueLabel.setText(String.valueOf(logsTable.getRowSorter().getViewRowCount()));
        }));
        resultsFilterBar.add(filteredCountValueLabel, gbc);
        JLabel totalCountValueLabel = new JLabel("/0");
        logEntriesManager.subscribeChangeListener(entriesCount -> SwingUtilities.invokeLater(() -> {
            filteredCountValueLabel.setText(String.valueOf(Math.min(entriesCount, logsTable.getRowSorter().getViewRowCount())));
            totalCountValueLabel.setText("/" + entriesCount);
        }));
        gbc = createGridConstraints(2, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        resultsFilterBar.add(totalCountValueLabel, gbc);

        JLabel resultsCountSeparator = new JLabel("│");
        gbc = createGridConstraints(3, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 10);
        resultsFilterBar.add(resultsCountSeparator, gbc);

        JLabel searchLabel = new JLabel(getLocaleString("logger-searchBar-label"));
        gbc = createGridConstraints(4, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        resultsFilterBar.add(searchLabel, gbc);

        JTextField searchField = new JTextField();
        gbc = createGridConstraints(5, 0, 1, 0, GridBagConstraints.HORIZONTAL);
        resultsFilterBar.add(searchField, gbc);

        JCheckBox regexCheckbox = new JCheckBox(getLocaleString(LogsTableModel.Column.REGEX.getLocaleKey()));
        regexCheckbox.setSelected(true);
        gbc = createGridConstraints(6, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        resultsFilterBar.add(regexCheckbox, gbc);

        JCheckBox matchCheckbox = new JCheckBox(getLocaleString(LogsTableModel.Column.MATCH.getLocaleKey()));
        matchCheckbox.setSelected(true);
        gbc = createGridConstraints(7, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        resultsFilterBar.add(matchCheckbox, gbc);

        JCheckBox URLCheckbox = new JCheckBox(getLocaleString(LogsTableModel.Column.URL.getLocaleKey()));
        URLCheckbox.setSelected(true);
        gbc = createGridConstraints(8, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        resultsFilterBar.add(URLCheckbox, gbc);

        JLabel filterUniqueSeparator = new JLabel("│");
        gbc = createGridConstraints(9, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        resultsFilterBar.add(filterUniqueSeparator, gbc);

        JCheckBox UniqueCheckbox = new JCheckBox(getLocaleString("logger-uniqueResults-label"));
        UniqueCheckbox.setSelected(false);
        gbc = createGridConstraints(10, 0, 0, 0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 0);
        resultsFilterBar.add(UniqueCheckbox, gbc);

        Runnable doUpdateRowFilter = () -> updateRowFilter(
                searchField.getText(),
                regexCheckbox.isSelected(),
                matchCheckbox.isSelected(),
                URLCheckbox.isSelected(),
                UniqueCheckbox.isSelected()
        );
        regexCheckbox.addActionListener(event -> doUpdateRowFilter.run());
        matchCheckbox.addActionListener(event -> doUpdateRowFilter.run());
        URLCheckbox.addActionListener(event -> doUpdateRowFilter.run());
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {
                doUpdateRowFilter.run();
            }

            @Override
            public void removeUpdate(DocumentEvent documentEvent) {
                doUpdateRowFilter.run();
            }

            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                doUpdateRowFilter.run();
            }
        });
        UniqueCheckbox.addActionListener(event -> doUpdateRowFilter.run());

        return resultsFilterBar;
    }

    private JPanel createAnalysisBar(JScrollPane logEntriesPane) {
        JPanel leftSidePanel;
        JPanel rightSidePanel;
        JPanel analysisBar;
        GridBagConstraints gbc;

        analysisBar = new JPanel();
        analysisBar.setLayout(new GridBagLayout());

        JProgressBar progressBar = new JProgressBar(0, 1);
        progressBar.setStringPainted(true);
        regexScanner.setProgressBar(progressBar);
        gbc = createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 10, 0, 10);
        analysisBar.add(progressBar, gbc);

        leftSidePanel = new JPanel();
        leftSidePanel.setLayout(new GridBagLayout());
        leftSidePanel.setPreferredSize(new Dimension(0, 40));
        analysisBar.add(leftSidePanel, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        JButton analysisButton = createAnalysisButton();
        leftSidePanel.add(analysisButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));
        final JPanel spacer2 = new JPanel();
        leftSidePanel.add(spacer2, createGridConstraints(0, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));

        rightSidePanel = new JPanel();
        rightSidePanel.setLayout(new GridBagLayout());
        rightSidePanel.setPreferredSize(new Dimension(0, 40));
        analysisBar.add(rightSidePanel, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.BOTH));
        JButton clearLogsButton = createClearLogsButton(logEntriesPane);
        gbc = createGridConstraints(0, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL);
        gbc.insets = new Insets(0, 0, 0, 5);
        rightSidePanel.add(clearLogsButton, gbc);
        final JPanel spacer1 = new JPanel();
        rightSidePanel.add(spacer1, createGridConstraints(2, 0, 1.0, 0.0, GridBagConstraints.HORIZONTAL));
        JToggleButton exportLogsButton = createExportLogsButton();
        rightSidePanel.add(exportLogsButton, createGridConstraints(1, 0, 0.0, 0.0, GridBagConstraints.HORIZONTAL));

        return analysisBar;
    }

    /**
     * Filter rows of LogsTable that contains text string
     *
     * @param text          text to search
     * @param includeRegex  if true, also search in Regex column
     * @param includeMatch  if true, also search in Match column
     * @param includeURL    if true, also search in URL column
     * @param uniqueResults if true, remove duplicate results
     */
    private void updateRowFilter(String text, boolean includeRegex, boolean includeMatch, boolean includeURL, boolean uniqueResults) {
        SwingUtilities.invokeLater(() -> {
            // hashmap to keep track of unique rows in the table
            final HashSet<Integer> uniqueResultsMap = new HashSet<>();

            logsTableRowSorter.setRowFilter(new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends LogsTableModel, ? extends Integer> entry) {
                    if (uniqueResults) {
                        int hashcode = entry.getModel().getRowHashcode(entry.getIdentifier());
                        if (uniqueResultsMap.contains(hashcode)) return false;
                        uniqueResultsMap.add(hashcode);
                    }
                    if (text.isBlank()) {
                        return true;
                    }
                    List<LogsTableModel.Column> places = new ArrayList<>();
                    if (includeRegex) places.add(LogsTableModel.Column.REGEX);
                    if (includeMatch) places.add(LogsTableModel.Column.MATCH);
                    if (includeURL) places.add(LogsTableModel.Column.URL);
                    return places.stream().anyMatch(column -> entry.getStringValue(column.getIndex()).toLowerCase().contains(text.toLowerCase()));
                }
            });
        });
    }

    /**
     * Creates a button that handles the analysis of the burp's http history
     *
     * @return the analysis button
     */
    private JButton createAnalysisButton() {
        JButton analysisButton = new JButton();
        String startAnalysisText = getLocaleString("logger-analysis-start");
        analysisButton.putClientProperty("initialText", startAnalysisText);
        analysisButton.setText(startAnalysisText);
        analysisButton.addActionListener(actionEvent -> {
            if (!isAnalysisRunning) {
                startAnalysisAction(analysisButton);
            } else {
                stopAnalysisAction(analysisButton);
            }
        });
        return analysisButton;
    }

    private void stopAnalysisAction(JButton analysisButton) {
        if (Objects.isNull(analyzeProxyHistoryThread)) return;

        SwingUtilities.invokeLater(() -> {
            analysisButton.setEnabled(false);
            analysisButton.setText(getLocaleString("logger-analysis-stopping"));
        });
        regexScanner.setInterruptScan(true);

        new Thread(() -> {
            try {
                analyzeProxyHistoryThread.join();
                regexScanner.setInterruptScan(false);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            SwingUtilities.invokeLater(() -> {
                analysisButton.setEnabled(true);
                analysisButton.setText(getLocaleString("logger-analysis-start"));
            });
        }).start();
    }

    private void startAnalysisAction(JButton analysisButton) {
        this.preAnalysisOperations();
        isAnalysisRunning = true;
        analyzeProxyHistoryThread = new Thread(new Runnable() {
            @Override
            public void run() {
                setupScan();
                startScan();
                finalizeScan();
            }

            private void setupScan() {
                SwingUtilities.invokeLater(() -> analysisButton.setText(getLocaleString("logger-analysis-stop")));
            }

            private void startScan() {
                Consumer<LogEntity> addLogEntryCallback = LoggerUtils.createAddLogEntryCallback(logEntriesManager, loggerLock, logsTableModel);
                regexScanner.analyzeProxyHistory(addLogEntryCallback);
            }

            private void finalizeScan() {
                SwingUtilities.invokeLater(() -> analysisButton.setText((String) analysisButton.getClientProperty("initialText")));
                analyzeProxyHistoryThread = null;
                isAnalysisRunning = false;
                LoggerTab.this.postAnalysisOperations();
            }
        });
        analyzeProxyHistoryThread.start();

        SwingUtilities.invokeLater(() -> {
            logsTable.validate();
            logsTable.repaint();
        });
    }

    private JScrollPane createLogEntriesTable() {
        logsTableModel = new LogsTableModel(logEntriesManager);
        this.originalRequestViewer = this.mainUI.getBurpApi().userInterface().createHttpRequestEditor();
        this.originalResponseViewer = this.mainUI.getBurpApi().userInterface().createHttpResponseEditor();
        this.logsTable = new LogsTable(logsTableModel, logEntriesManager, this.originalRequestViewer, this.originalResponseViewer);
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
                    LogEntity logEntry = logEntriesManager.get(realRow);

                    if (e.getComponent() instanceof LogsTable) {
                        new LogsTableContextMenu(logEntry, logEntriesManager, originalRequestViewer, originalResponseViewer, logsTableModel, logsTable, mainUI.getBurpApi(), isAnalysisRunning)
                                .show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        };
        logsTable.addMouseListener(contextMenu);

        return new JScrollPane(logsTable);
    }

    private List<LogsTableModel.Column> getExportableColumns() {
        return List.of(
                LogsTableModel.Column.MATCH,
                LogsTableModel.Column.REGEX,
                LogsTableModel.Column.URL
        );
    }

    private JToggleButton createExportLogsButton() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem itemToCSV = new JMenuItem(getLocaleString("common-toCSV"));
        itemToCSV.addActionListener(actionEvent -> {
            String csvFile = SwingUtils.selectFile(List.of("CSV"), false);
            if (csvFile.isBlank()) return;

            java.util.List<String> lines = new ArrayList<>();

            List<LogsTableModel.Column> columns = getExportableColumns();
            String header = columns.stream()
                    .map(LogsTableModel.Column::getNameFormatted)
                    .map(s -> '"' + s + '"')
                    .collect(Collectors.joining(","));
            lines.add(header);

            for (int i = 0; i < logsTable.getRowCount(); i++) {
                final int rowIndex = i;
                String line = columns.stream()
                        .map(LogsTableModel.Column::getIndex)
                        .map(columnIdx -> logsTableModel.getValueAt(logsTable.convertRowIndexToModel(rowIndex), columnIdx))
                        .map(cellValue -> cellValue.toString().replaceAll("\"", "\"\""))
                        .map(s -> '"' + s + '"')
                        .collect(Collectors.joining(","));
                lines.add(line);
            }

            FileUtils.writeLinesToFile(csvFile, lines);
        });
        menu.add(itemToCSV);

        JMenuItem itemToJSON = new JMenuItem(getLocaleString("common-toJSON"));
        itemToJSON.addActionListener(actionEvent -> {
            String jsonFile = SwingUtils.selectFile(List.of("JSON"), false);
            if (jsonFile.isBlank()) return;

            List<LogsTableModel.Column> fields = getExportableColumns();
            List<JsonObject> lines = new ArrayList<>();

            for (int i = 0; i < logsTable.getRowCount(); i++) {
                JsonObject json = new JsonObject();
                for (LogsTableModel.Column column : fields) {
                    json.addProperty(column.getNameFormatted(), logsTableModel.getValueAt(logsTable.convertRowIndexToModel(i), column.getIndex()).toString());
                }
                lines.add(json);
            }

            String json = createGsonBuilder().toJson(lines, (new TypeToken<ArrayList<JsonObject>>() {
            }).getType());
            FileUtils.writeLinesToFile(jsonFile, List.of(json));
        });
        menu.add(itemToJSON);

        PopupMenuButton btnExportLogs = new PopupMenuButton(getLocaleString("logger-exportLogs-label"), menu);
        btnExportLogs.putClientProperty("analysisDependent", "1");

        return btnExportLogs;
    }

    private JButton createClearLogsButton(JScrollPane scrollPaneLogger) {
        JButton btnClearLogs = new JButton(getLocaleString("logger-clearLogs-label"));
        btnClearLogs.addActionListener(e -> {
            int dialog = JOptionPane.showConfirmDialog(
                    null,
                    getLocaleString("logger-clearLogs-message"),
                    getLocaleString("logger-clearLogs-title"),
                    JOptionPane.YES_NO_OPTION);
            if (dialog == JOptionPane.YES_OPTION) {
                logEntriesManager.clear();
                logsTableModel.fireTableDataChanged();

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
