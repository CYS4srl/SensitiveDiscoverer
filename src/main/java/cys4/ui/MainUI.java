/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.ITextEditor;
import burp.SpringUtilities;
import cys4.model.ExtensionEntity;
import cys4.model.LogEntity;
import cys4.model.RegexEntity;
import cys4.scanner.BurpLeaksScanner;
import cys4.seed.BurpLeaksSeed;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Scanner;

public class MainUI implements ITab {

    // default options
    private Properties _PROPERTIES_PluginProperties;

    // ui components
    private LogTableEntriesUI logTableEntriesUI;
    private LogTableEntryUI logTableEntryUI;
    private JSplitPane splitPane;
    private ITextEditor originalRequestViewer;
    private ITextEditor originalResponseViewer;
    private static IBurpExtenderCallbacks callbacks;

    /**
     * Analyze Proxy History
     */
    private Thread analyzeProxyHistoryThread;
    private boolean isAnalysisRunning;

    private List<LogEntity> _lLogEntries;
    private List<RegexEntity> _lRegexes;
    private List<ExtensionEntity> _lExtensions;

    private BurpLeaksScanner burpLeaksScanner;

    /**
     * Check if the options for the scope is selected or not
     */
    private static boolean inScope = false;

    public MainUI(List<RegexEntity> regexList, List<ExtensionEntity> extensionList, IBurpExtenderCallbacks callbacks) {

        this._lLogEntries = new ArrayList<>();

        // Dipendency Injection
        this._lRegexes = regexList;
        this._lExtensions = extensionList;
        this.callbacks = callbacks;

        // Analyze Proxy History
        this.analyzeProxyHistoryThread = null;
        this.isAnalysisRunning = false;

        // init the other UI elements
        logTableEntriesUI = new LogTableEntriesUI(this._lLogEntries);

        originalRequestViewer = callbacks.createTextEditor();
        originalResponseViewer = callbacks.createTextEditor();
        logTableEntryUI = new LogTableEntryUI(logTableEntriesUI, this._lLogEntries, this.originalRequestViewer, this.originalResponseViewer);

        burpLeaksScanner = new BurpLeaksScanner(this, callbacks, _lLogEntries, this._lRegexes, this._lExtensions );

        LoadConfigFile();
    }

    private void LoadConfigFile() {
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

    // GetNameExtension return the name of the extension from the configuration file
    public String getNameExtension() {
        return _PROPERTIES_PluginProperties.getProperty("ui.name.extension_name");
    }

    // isInScope return true if the option is selected
    public static boolean isInScope() {
        return inScope;
    }

    // used by the burp extender to add a new entry
    public void logTableEntriesUIAddNewRow(int row) {
        logTableEntriesUI.addNewRow(row);
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    //TODO: docs & refactor
    public void createUI() {
        // Updates the UI in async method
        SwingUtilities.invokeLater(() -> {
            // main panel; it shows logger and options tabs
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            JTabbedPane tabbedPane = new JTabbedPane();
            JPanel tabPanelLogger, tabPaneOptions;
            tabPanelLogger = new JPanel();
            tabPanelLogger.setLayout(new BoxLayout(tabPanelLogger, BoxLayout.Y_AXIS));

            tabPaneOptions = new JPanel();
            tabPaneOptions.setLayout(new BoxLayout(tabPaneOptions, BoxLayout.Y_AXIS));

            tabbedPane.addTab("Logger", tabPanelLogger);
            tabbedPane.addTab("Options", tabPaneOptions);

            splitPane.add(tabbedPane);

            // when you right click on a logTable entry, it will appear a context menu defined here
            MouseAdapter contextMenu = new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    onMouseEvent(e);
                }

                private void onMouseEvent(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        int row = logTableEntryUI.getSelectedRow();
                        logTableEntryUI.setRowSelectionInterval(row, row);
                        if (logTableEntryUI.getSelectedRowCount() == 1) {
                            int realRow = logTableEntryUI.convertRowIndexToModel(row);
                            LogEntity logentry = _lLogEntries.get(realRow);

                            if (e.getComponent() instanceof LogTableEntryUI) {
                                new ContextMenuUI(logentry, _lLogEntries, originalRequestViewer, originalResponseViewer, logTableEntriesUI, logTableEntryUI, callbacks).show(e.getComponent(), e.getX(), e.getY());
                            }
                        }
                    }
                }
            };
            logTableEntryUI.addMouseListener(contextMenu);
            ListSelectionModel listSelectionModel = logTableEntryUI.getSelectionModel();
            logTableEntryUI.setSelectionModel(listSelectionModel);
            JScrollPane scrollPaneLogger = new JScrollPane(logTableEntryUI);
            tabPanelLogger.setLayout(new BorderLayout());

            // Table of regex and extensions options
            String title = "CONFIGURATION OPTIONS";
            Border border = BorderFactory.createTitledBorder(title);
            tabPaneOptions.setBorder(border);

            // SHOW ONLY IN-SCOPE ITEMS
            JPanel inScopePanel = new JPanel();
            inScopePanel.setAlignmentX(Component.RIGHT_ALIGNMENT);
            inScopePanel.setPreferredSize(new Dimension(1000, 50));
            inScopePanel.setMaximumSize(new Dimension(1000, 50));
            tabPaneOptions.add(inScopePanel);
            JLabel jLabelInScope = new JLabel();
            jLabelInScope.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
            jLabelInScope.setForeground(new Color(255, 102, 51));
            jLabelInScope.setText("Filters\r\n");
            JCheckBox inScopeCheckBox = new JCheckBox("Show only in-scope items");
            inScopePanel.setLayout(new BoxLayout(inScopePanel, BoxLayout.Y_AXIS));
            inScopePanel.add(jLabelInScope);
            inScopePanel.add(inScopeCheckBox);
            inScopeCheckBox.addActionListener(e -> {
                if (inScopeCheckBox.getModel().isSelected()) {
                    inScope = true;
                } else if (!inScopeCheckBox.getModel().isSelected()) {
                    inScope = false;
                }
            });

            tabPaneOptions.add(new JSeparator());

            // START Table 1 - REGEX
            OptionsRegexTableModelUI modelReg = new OptionsRegexTableModelUI(_lRegexes);
            JTable optionsRegexTable = new JTable(modelReg);
            JPanel titlePanelRegex = new JPanel();
            titlePanelRegex.setAlignmentX(Component.RIGHT_ALIGNMENT);
            titlePanelRegex.setPreferredSize(new Dimension(1000, 50));
            titlePanelRegex.setMaximumSize(new Dimension(1000, 50));
            tabPaneOptions.add(titlePanelRegex);
            titlePanelRegex.setLayout(new BoxLayout(titlePanelRegex, BoxLayout.Y_AXIS));
            JLabel jLabelRegexList = new JLabel();
            jLabelRegexList.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
            jLabelRegexList.setForeground(new Color(255, 102, 51));
            JLabel jlabelSpace = new JLabel();
            jlabelSpace.setText(" \n");
            titlePanelRegex.add(jlabelSpace);
            jLabelRegexList.setText("Regex List\n");
            titlePanelRegex.add(jLabelRegexList);
            JLabel jLabelRegexDescription = new JLabel();
            jLabelRegexDescription.setText("In this section you can manage the regex list. ");
            titlePanelRegex.add(jLabelRegexDescription);

            // Button Panel for starting analysis
            JPanel buttonPanelLog = new JPanel();
            buttonPanelLog.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
            tabPanelLogger.add(buttonPanelLog);

            // Button Panel REGEX
            JPanel buttonPanelRegex = new JPanel();
            tabPaneOptions.add(buttonPanelRegex, BorderLayout.WEST);

            JButton btnResetRegex = new JButton("Reset");
            buttonPanelRegex.add(btnResetRegex);
            btnResetRegex.addActionListener(actionEvent -> {
                // start from the end and iterate to the beginning to delete because when you delete,
                // it is deleting elements from data, and you are skipping some rows when you iterate
                // to the next element (via i++)
                int dialog = JOptionPane.showConfirmDialog(null, "By confirming, you will return to init setting");
                if (dialog == JOptionPane.YES_OPTION) {
                    if (_lRegexes.size() > 0) {
                        _lRegexes.subList(0, _lRegexes.size()).clear();
                    }
                    _lRegexes = BurpLeaksSeed.getRegex();
                    modelReg.fireTableDataChanged();
                }

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnNewRegex = new JButton("New");
            buttonPanelRegex.add(btnNewRegex);
            btnNewRegex.addActionListener(actionEvent -> {
                String[] labels = {"Regex: ", "Description: "};
                //Create and populate the panel.
                JPanel inputPanel = new JPanel(new SpringLayout());
                JLabel labelExpression = new JLabel(labels[0], JLabel.TRAILING);
                inputPanel.add(labelExpression);
                JTextField textFieldReg = new JTextField(10);
                labelExpression.setLabelFor(textFieldReg);
                inputPanel.add(textFieldReg);
                JLabel labelDescription = new JLabel(labels[1], JLabel.TRAILING);
                inputPanel.add(labelDescription);
                JTextField textFieldDesc = new JTextField(10);
                labelDescription.setLabelFor(textFieldDesc);
                inputPanel.add(textFieldDesc);
                //Lay out the panel.
                SpringUtilities.makeCompactGrid(inputPanel,
                        labels.length, 2, //rows, cols
                        6, 6,        //initX, initY
                        6, 6);       //xPad, yPad
                int returnValue = JOptionPane.showConfirmDialog(tabPaneOptions, inputPanel, "Add a regular expression", JOptionPane.YES_NO_OPTION);
                if (returnValue == JOptionPane.YES_OPTION) {
                    String expression = textFieldReg.getText();
                    String description = textFieldDesc.getText();
                    int row = _lRegexes.size();
                    _lRegexes.add(new RegexEntity(description, expression));
                    modelReg.fireTableRowsInserted(row, row);
                }
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnDeleteRegex = new JButton("Delete");
            buttonPanelRegex.add(btnDeleteRegex);
            btnDeleteRegex.addActionListener(actionEvent -> {
                int rowIndex = optionsRegexTable.getSelectedRow();
                int realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);
                _lRegexes.remove(realRow);

                modelReg.fireTableRowsDeleted(realRow, realRow);

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnClearRegex = new JButton("Clear");
            buttonPanelRegex.add(btnClearRegex);
            btnClearRegex.addActionListener(actionEvent -> {
                int dialog = JOptionPane.showConfirmDialog(null, "Delete ALL the regex in the list?");
                if (dialog == JOptionPane.YES_OPTION) {
                    if (_lRegexes.size() > 0) {
                        _lRegexes.subList(0, _lRegexes.size()).clear();
                    }
                }

                modelReg.fireTableDataChanged();
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnOpenRegex = new JButton("Open");
            buttonPanelRegex.add(btnOpenRegex);
            btnOpenRegex.addActionListener(actionEvent -> {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        ".txt, .csv", "txt", "csv");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonPanelRegex);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    System.out.println("You chose to open this file: " +
                            chooser.getSelectedFile().getName());
                }
                try {
                    Scanner scanner = new Scanner(chooser.getSelectedFile());
                    StringBuilder alreadyAdded = new StringBuilder();
                    while (scanner.hasNextLine()) {
                        String line = scanner.nextLine();
                        if (RegexEntity.regexIsInCorrectFormat(line)) {
                            String description = line.split("\", \"")[0];
                            description = description.substring(0, description.length() - 1);
                            String regex = line.split("\", \"")[1];
                            regex = regex.substring(0, regex.length() - 1);
                            RegexEntity newRegexEntity = new RegexEntity(description, regex);
                            if (!_lRegexes.contains(newRegexEntity)) {
                                _lRegexes.add(newRegexEntity);
                            } else {
                                alreadyAdded.append(description).append(" - ").append(regex).append("\n");
                            }
                            int row = _lRegexes.size();
                            modelReg.fireTableRowsInserted(row, row);
                            tabPaneOptions.validate();
                            tabPaneOptions.repaint();
                        }
                    }

                    if (!(alreadyAdded.toString().equals(""))) {
                        alreadyAdded.insert(0, "These regex are already present:\n");
                        JDialog alreadyAddedDialog = new JDialog();
                        JOptionPane.showMessageDialog(alreadyAddedDialog, alreadyAdded.toString(), "Already Added Alert", JOptionPane.INFORMATION_MESSAGE);

                        alreadyAddedDialog.setVisible(true);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnSaveRegex = new JButton("Save");
            buttonPanelRegex.add(btnSaveRegex);
            btnSaveRegex.addActionListener(actionEvent -> {
                JFrame parentFrame = new JFrame();
                JFileChooser fileChooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(".txt, .csv", "txt", "csv");
                fileChooser.setFileFilter(filter);
                fileChooser.setDialogTitle("Specify a file to save");
                int userSelection = fileChooser.showSaveDialog(parentFrame);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    try {
                        PrintWriter pwt;
                        pwt = new PrintWriter(fileToSave.getAbsolutePath());

                        for (int i = 0; i < modelReg.getRowCount(); i++) {
                            String regex = modelReg.getValueAt(i, 1).toString();
                            String description = modelReg.getValueAt(i, 2).toString();
                            pwt.println("\"" + regex + "\"," + "\"" + description + "\"");
                        }
                        pwt.close();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                }
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });


            optionsRegexTable.setAutoCreateRowSorter(true);

            JScrollPane scrollPaneRegOptions = new JScrollPane(optionsRegexTable);
            scrollPaneRegOptions.setBorder(BorderFactory.createCompoundBorder(new EmptyBorder(0, 0, 20, 0), new EtchedBorder()));
            tabPaneOptions.add(scrollPaneRegOptions);
            optionsRegexTable.getColumnModel().getColumn(0).setMinWidth(80);
            optionsRegexTable.getColumnModel().getColumn(0).setMaxWidth(80);
            optionsRegexTable.getColumnModel().getColumn(0).setPreferredWidth(80);

            // END Table 1 - REGEX

            tabPaneOptions.add(new JSeparator());

            // START Table 2 - EXTENSION
            OptionsExtTableModelUI modelExt = new OptionsExtTableModelUI(_lExtensions);
            JPanel titlePanelExtensions = new JPanel();
            titlePanelExtensions.setAlignmentX(Component.RIGHT_ALIGNMENT);
            titlePanelExtensions.setPreferredSize(new Dimension(1000, 50));
            titlePanelExtensions.setMaximumSize(new Dimension(1000, 50));
            tabPaneOptions.add(titlePanelExtensions);
            titlePanelExtensions.setLayout(new BoxLayout(titlePanelExtensions, BoxLayout.Y_AXIS));
            JLabel jLabelExtensionsList = new JLabel();
            jLabelExtensionsList.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
            jLabelExtensionsList.setForeground(new Color(255, 102, 51));
            JLabel jlabelSpace2 = new JLabel();
            jlabelSpace2.setText(" \n");
            titlePanelExtensions.add(jlabelSpace2);
            jLabelExtensionsList.setText("Extensions List");
            titlePanelExtensions.add(jLabelExtensionsList);
            JLabel jLabelExtensionsDescription = new JLabel();
            jLabelExtensionsDescription.setText("In this section you can manage the extension list. ");
            titlePanelExtensions.add(jLabelExtensionsDescription);

            // Button Panel EXTENSION
            JTable optionExtensionsTable = new JTable(modelExt);
            JPanel buttonPanelExtensions = new JPanel();
            tabPaneOptions.add(buttonPanelExtensions, BorderLayout.WEST);

            JButton btnResetExtension = new JButton("Reset");
            buttonPanelExtensions.add(btnResetExtension);
            btnResetExtension.addActionListener(actionEvent -> {
                // start from the end and iterate to the beginning to delete because when you delete,
                // it is deleting elements from data, and you are skipping some rows when you iterate
                // to the next element (via i++)
                int dialog = JOptionPane.showConfirmDialog(null, "By confirming, you will return to init setting");
                if (dialog == JOptionPane.YES_OPTION) {
                    if (_lExtensions.size() > 0) {
                        _lExtensions.subList(0, _lExtensions.size()).clear();
                    }

                }
                _lExtensions = BurpLeaksSeed.getExtensions();
                modelExt.fireTableDataChanged();
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnNewExtension = new JButton("New");
            buttonPanelExtensions.add(btnNewExtension);
            btnNewExtension.addActionListener(actionEvent -> {
                String[] labels = {"Extension: ", "Description: "};
                //Create and populate the panel.
                JPanel inputPanel = new JPanel(new SpringLayout());
                JLabel labelExtension = new JLabel(labels[0], JLabel.TRAILING);
                inputPanel.add(labelExtension);
                JTextField textFieldExt = new JTextField(10);
                labelExtension.setLabelFor(textFieldExt);
                inputPanel.add(textFieldExt);
                JLabel labelDescription = new JLabel(labels[1], JLabel.TRAILING);
                inputPanel.add(labelDescription);
                JTextField textFieldDesc = new JTextField(10);
                labelDescription.setLabelFor(textFieldDesc);
                inputPanel.add(textFieldDesc);
                //Lay out the panel.
                SpringUtilities.makeCompactGrid(inputPanel,
                        labels.length, 2, //rows, cols
                        6, 6,        //initX, initY
                        6, 6);       //xPad, yPad
                int returnValue = JOptionPane.showConfirmDialog(tabPaneOptions, inputPanel, "Add an extension", JOptionPane.YES_NO_OPTION);
                if (returnValue == JOptionPane.YES_OPTION) {
                    String extension = textFieldExt.getText();
                    String description = textFieldDesc.getText();

                    if (ExtensionEntity.extIsInCorrectFormat("\"" + description + "\",\"" + extension + "\"")) {
                        int row = _lExtensions.size();
                        _lExtensions.add(new ExtensionEntity(description, "\\" + extension));
                        modelExt.fireTableRowsInserted(row, row);
                    } else {
                        JOptionPane.showMessageDialog(tabPaneOptions, "Input data has wrong format. Can't add the new extension\n\nUsage: Extension: .ext - Description: whatever");
                    }
                }
            });

            JButton btnDeleteExtension = new JButton("Delete");
            buttonPanelExtensions.add(btnDeleteExtension);
            btnDeleteExtension.addActionListener(actionEvent -> {
                int rowIndex = optionExtensionsTable.getSelectedRow();
                int realRow = optionExtensionsTable.convertRowIndexToModel(rowIndex);
                _lExtensions.remove(realRow);
                modelExt.fireTableRowsDeleted(realRow, realRow);

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnClearExtension = new JButton("Clear");
            buttonPanelExtensions.add(btnClearExtension);
            btnClearExtension.addActionListener(actionEvent -> {
                int dialog = JOptionPane.showConfirmDialog(null, "Delete ALL the extensions in the list?");
                if (dialog == JOptionPane.YES_OPTION) {
                    _lExtensions.clear();
                    modelExt.fireTableDataChanged();
                }
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnOpenExtension = new JButton("Open");
            buttonPanelExtensions.add(btnOpenExtension);
            btnOpenExtension.addActionListener(actionEvent -> {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        ".txt, .csv", "txt", "csv");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonPanelExtensions);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    System.out.println("You chose to open this file: " +
                            chooser.getSelectedFile().getName());
                }
                try {
                    Scanner scanner = new Scanner(chooser.getSelectedFile());
                    StringBuilder alreadyAdded = new StringBuilder();
                    while (scanner.hasNextLine()) {
                        String line = scanner.nextLine();
                        if (ExtensionEntity.extIsInCorrectFormat(line)) {
                            String regex = line.split(",")[0];
                            regex = regex.substring(1, regex.length() - 1);

                            String description = line.split(",")[1];
                            description = description.substring(1, description.length() - 1);

                            ExtensionEntity extension = new ExtensionEntity(regex, description);

                            if (!_lExtensions.contains(extension)) {
                                _lExtensions.add(extension);
                            } else {
                                alreadyAdded.append(description).append(" - ").append(regex).append("\n");
                            }
                            int row = _lExtensions.size();

                            modelExt.fireTableRowsInserted(row, row);

                            tabPaneOptions.validate();
                            tabPaneOptions.repaint();
                        }
                    }

                    if (!(alreadyAdded.toString().equals(""))) {
                        alreadyAdded.insert(0, "These extensions are already present:\n");
                        JDialog alreadyAddedDialog = new JDialog();
                        JOptionPane.showMessageDialog(alreadyAddedDialog, alreadyAdded.toString(), "Already Added Alert", JOptionPane.INFORMATION_MESSAGE);

                        alreadyAddedDialog.setVisible(true);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            JButton btnSaveExtension = new JButton("Save");
            buttonPanelExtensions.add(btnSaveExtension);
            btnSaveExtension.addActionListener(actionEvent -> {
                JFrame parentFrame = new JFrame();

                JFileChooser fileChooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Regex list", "txt", "csv");
                fileChooser.setFileFilter(filter);
                fileChooser.setDialogTitle("Specify a file to save");

                int userSelection = fileChooser.showSaveDialog(parentFrame);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    try {
                        PrintWriter pwt;
                        if (!fileToSave.getAbsolutePath().contains(".txt")) {
                            pwt = new PrintWriter(fileToSave.getAbsolutePath() + "_extensions.txt");
                        } else {
                            pwt = new PrintWriter(fileToSave.getAbsolutePath());
                        }
                        for (int i = 0; i < modelReg.getRowCount(); i++) {
                            String regex = modelReg.getValueAt(i, 1).toString();
                            String description = modelReg.getValueAt(i, 2).toString();
                            pwt.println("\"" + regex + "\"," + "\"" + description + "\"");
                        }
                        pwt.close();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                }

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            });

            // table of regex options

            optionExtensionsTable.setAutoCreateRowSorter(true);

            JScrollPane scrollPaneExtOptions = new JScrollPane(optionExtensionsTable);
            tabPaneOptions.add(scrollPaneExtOptions);
            optionExtensionsTable.getColumnModel().getColumn(0).setMinWidth(80);
            optionExtensionsTable.getColumnModel().getColumn(0).setMaxWidth(80);
            optionExtensionsTable.getColumnModel().getColumn(0).setPreferredWidth(80);

            // END Table 2 - EXTENSION


            //   begin   LOGGER PANEL

            // buttons: Analyze Http History and Clear Logs
            //TODO: move strings to a single place
            final String textAnalysisStart = "Analyze HTTP History";
            final String textAnalysisStop = "Stop analysis";
            final String textAnalysisStopping = "Stopping the analysis...";

            JButton btnStartAnalysis = new JButton(textAnalysisStart);
            buttonPanelLog.add(btnStartAnalysis, BorderLayout.NORTH);

            JProgressBar progressBar = new JProgressBar(0, 1);
            buttonPanelLog.add(progressBar, BorderLayout.NORTH);

            btnStartAnalysis.addActionListener(actionEvent -> {
                if (!isAnalysisRunning) {
                    if (callbacks.getProxyHistory().length > 0) {
                        this.isAnalysisRunning = true;
                        this.analyzeProxyHistoryThread = new Thread(() -> {
                            String previousText = btnStartAnalysis.getText();
                            btnStartAnalysis.setText(textAnalysisStop);
                            logTableEntryUI.setAutoCreateRowSorter(false);

                            burpLeaksScanner.analyzeProxyHistory(progressBar);

                            btnStartAnalysis.setText(previousText);
                            logTableEntryUI.setAutoCreateRowSorter(true);
                            this.analyzeProxyHistoryThread = null;
                            this.isAnalysisRunning = false;
                        });
                        this.analyzeProxyHistoryThread.start();

                        //TODO: are they needed?
                        // logTableEntryUI.validate();
                        // logTableEntryUI.repaint();
                    }
                } else {
                    if (Objects.isNull(this.analyzeProxyHistoryThread)) return;

                    btnStartAnalysis.setEnabled(false);
                    btnStartAnalysis.setText(textAnalysisStopping);
                    burpLeaksScanner.interruptScan = true;

                    new Thread(() -> {
                        try {
                            this.analyzeProxyHistoryThread.join();
                            burpLeaksScanner.interruptScan = false;
                        } catch (InterruptedException e1) {
                            e1.printStackTrace();
                        }
                        btnStartAnalysis.setEnabled(true);
                        btnStartAnalysis.setText(textAnalysisStart);
                    }).start();
                }

                //TODO: are they needed?
                // tabPanelLogger.validate();
                // tabPanelLogger.repaint();
            });

            JButton btnClearLogs = new JButton("Clear Logs");
            buttonPanelLog.add(btnClearLogs, BorderLayout.NORTH);
            btnClearLogs.addActionListener(e -> {
                int dialog = JOptionPane.showConfirmDialog(null, "Delete ALL the logs in the list?");
                if (dialog == JOptionPane.YES_OPTION) {
                    _lLogEntries.clear();
                    logTableEntriesUI.clear();

                    originalResponseViewer.setText(new byte[0]);
                    originalResponseViewer.setSearchExpression("");
                    originalRequestViewer.setText(new byte[0]);
                }

                scrollPaneLogger.validate();
                scrollPaneLogger.repaint();
            });

            // Request / Response viewers under the logger
            JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            requestResponseSplitPane.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
            JPanel requestResponsePanel = new JPanel();
            requestResponsePanel.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
            requestResponsePanel.add(requestResponseSplitPane);

            // the 2 panels under the logger

            JPanel originalRequestPanel = new JPanel();
            JLabel originalRequestLabel = new JLabel("Request");
            originalRequestLabel.setFont(new Font("Lucida Grande", Font.BOLD, 14)); // NOI18N
            originalRequestLabel.setForeground(new Color(255, 102, 51));
            originalRequestPanel.add(originalRequestLabel);
            originalRequestPanel.add(originalRequestViewer.getComponent());

            JPanel originalResponsePanel = new JPanel();
            JLabel originalResponseLabel = new JLabel("Response");
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

            // panel that contains the 2 analysis buttons and the logger
            JPanel buttonsLoggerPanel = new JPanel();
            buttonsLoggerPanel.setLayout(new BoxLayout(buttonsLoggerPanel, BoxLayout.Y_AXIS));
            buttonsLoggerPanel.setLayout(new BorderLayout());
            buttonsLoggerPanel.add(buttonPanelLog, BorderLayout.NORTH);
            buttonsLoggerPanel.add(scrollPaneLogger, BorderLayout.CENTER);

            // panel that contains all the graphical elements in the Logger Panel
            JSplitPane mainLoggerPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buttonsLoggerPanel, requestResponseSplitPane);
            tabPanelLogger.add(mainLoggerPanel);

            // END of Logger Panel

            // customize our UI components
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(logTableEntryUI);
            callbacks.customizeUiComponent(optionsRegexTable);
            callbacks.customizeUiComponent(optionExtensionsTable);
            callbacks.customizeUiComponent(mainLoggerPanel);
            callbacks.customizeUiComponent(scrollPaneLogger);
            callbacks.customizeUiComponent(requestResponseSplitPane);
            callbacks.customizeUiComponent(scrollPaneRegOptions);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(MainUI.this);

        });
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
