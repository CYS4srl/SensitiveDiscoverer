package com.cys4.sensitivediscoverer.ui;

import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.ui.table.RegexListTable;
import com.cys4.sensitivediscoverer.ui.table.RegexListTableModel;
import com.cys4.sensitivediscoverer.utils.FileUtils;
import com.cys4.sensitivediscoverer.utils.SwingUtils;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

public class RegexListPanel {
    private final JPanel panel;

    /**
     * Creates a JPanel to view regexes in a table, and to make operations on these regexes.
     * <br><br>
     * The components are mainly a table to display the regexes and some buttons to do operations on the list.
     * The input regexEntities is modified accordingly each time an action is performed.
     *
     * @param regexEntities    The list of regexes that the list keeps track of.
     * @param resetRegexSeeder default set of regexes when the list is cleared.
     */
    public RegexListPanel(String title,
                          String description,
                          List<RegexEntity> regexEntities,
                          Supplier<List<RegexEntity>> resetRegexSeeder) {
        this.panel = createRegexList(title, description, regexEntities, resetRegexSeeder);
    }

    public JPanel getPanel() {
        return panel;
    }

    private JPanel createRegexList(String title,
                                   String description,
                                   List<RegexEntity> regexEntities,
                                   Supplier<List<RegexEntity>> resetRegexSeeder) {
        JPanel container;
        JPanel header;
        JPanel body;

        container = new JPanel();
        container.setLayout(new BorderLayout(0, 0));
        container.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));

        header = createRegexListHeader(title, description);
        container.add(header, BorderLayout.NORTH);

        body = createRegexListBody(regexEntities, resetRegexSeeder);
        container.add(body, BorderLayout.CENTER);

        return container;
    }

    private GridBagConstraints createGridConstraints(int gridx, int gridy, double weightx, double weighty, int anchor) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gridx;
        gbc.gridy = gridy;
        gbc.weightx = weightx;
        gbc.weighty = weighty;
        gbc.anchor = anchor;
        return gbc;
    }

    private GridBagConstraints createButtonGridConstraints(int gridx, int gridy) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gridx;
        gbc.gridy = gridy;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(gridy == 0 ? 0 : 7, 7, 0, 0);
        gbc.ipadx = 35;
        gbc.ipady = 8;
        return gbc;
    }

    private JPanel createRegexListHeader(String title, String description) {
        JPanel header;
        GridBagConstraints gbc;

        header = new JPanel();
        header.setLayout(new GridBagLayout());
        header.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));

        JLabel titleLabel = new JLabel();
        titleLabel.setFont(MainUI.UIOptions.H1_FONT);
        titleLabel.setForeground(MainUI.UIOptions.ACCENT_COLOR);
        titleLabel.setText(title);
        gbc = createGridConstraints(0, 0, 0.0, 1.0, GridBagConstraints.WEST);
        gbc.insets = new Insets(0, 0, 1, 0);
        header.add(titleLabel, gbc);

        JLabel subtitleLabel = new JLabel();
        subtitleLabel.setText(description);
        gbc = createGridConstraints(0, 1, 0.0, 1.0, GridBagConstraints.WEST);
        header.add(subtitleLabel, gbc);

        final JPanel spacer = new JPanel();
        gbc = createGridConstraints(1, 0, 1.0, 0.0, GridBagConstraints.CENTER);
        gbc.gridheight = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        header.add(spacer, gbc);

        return header;
    }

    private JPanel createRegexListBody(List<RegexEntity> regexEntities, Supplier<List<RegexEntity>> resetRegexSeeder) {
        JPanel container;
        JPanel containerRight;
        JPanel containerCenter;
        GridBagConstraints gbc;

        RegexListTableModel tableModel = new RegexListTableModel(regexEntities);

        container = new JPanel(new BorderLayout(0, 0));
        containerCenter = new JPanel(new GridBagLayout());
        container.add(containerCenter, BorderLayout.CENTER);
        containerRight = new JPanel(new GridBagLayout());
        container.add(containerRight, BorderLayout.EAST);

        // table
        JTable regexTable = new RegexListTable(tableModel);
        final JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(regexTable);
        gbc = createGridConstraints(0, 0, 1.0, 1.0, GridBagConstraints.CENTER);
        gbc.fill = GridBagConstraints.BOTH;
        containerCenter.add(scrollPane, gbc);

        // popup menu
        regexTable.addMouseListener(createRegexPopupMenu(regexEntities, regexTable, containerCenter, tableModel));

        // buttons
        JButton enableAllButton = createSetEnabledButton(regexEntities, true, containerCenter, tableModel);
        containerRight.add(enableAllButton, createButtonGridConstraints(0, 0));
        JButton disableAllButton = createSetEnabledButton(regexEntities, false, containerCenter, tableModel);
        containerRight.add(disableAllButton, createButtonGridConstraints(0, 1));

        JPopupMenu listMenu = new JPopupMenu();
        listMenu.add(createListClearMenuItem(regexEntities, containerCenter, tableModel));
        listMenu.add(createListResetMenuItem(regexEntities, resetRegexSeeder, containerCenter, tableModel));
        listMenu.add(createListOpenMenuItem(regexEntities, containerCenter, tableModel));
        listMenu.add(createListSaveMenuItem(regexEntities));
        JToggleButton listButton = new PopupMenuButton(getLocaleString("options-list-listSubmenu"), listMenu);
        containerRight.add(listButton, createButtonGridConstraints(0, 2));

        JPopupMenu regexMenu = new JPopupMenu();
        regexMenu.add(createNewRegexMenuItem(regexEntities, containerCenter, tableModel));
        regexMenu.add(createEditRegexMenuItem(regexEntities, regexTable, containerCenter, tableModel));
        regexMenu.add(createDeleteRegexMenuItem(regexEntities, regexTable, containerCenter, tableModel));
        JToggleButton regexButton = new PopupMenuButton(getLocaleString("options-list-regexSubmenu"), regexMenu);
        containerRight.add(regexButton, createButtonGridConstraints(0, 3));

        return container;
    }

    /**
     * Create a popup menu over the selected regexTable entry and show edit and delete buttons.
     *
     * @param regexEntities
     * @param regexTable
     * @param tabPaneOptions
     * @param tableModel
     */
    private MouseListener createRegexPopupMenu(List<RegexEntity> regexEntities, JTable regexTable, JPanel tabPaneOptions, RegexListTableModel tableModel) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                onMouseEvent(e);
            }

            private void onMouseEvent(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = regexTable.getSelectedRow();
                    if (row == -1) return;
                    if (e.getComponent() instanceof JTable) {
                        JPopupMenu regexMenu = new JPopupMenu();
                        regexMenu.add(new JMenuItem(new AbstractAction(getLocaleString("options-list-edit")) {
                            @Override
                            public void actionPerformed(final ActionEvent e) {
                                editSelectedRegex(regexEntities, regexTable, tabPaneOptions, tableModel);
                            }
                        }));
                        regexMenu.add(new JMenuItem(new AbstractAction(getLocaleString("options-list-delete")) {
                            @Override
                            public void actionPerformed(final ActionEvent e) {
                                deleteSelectedRegex(regexEntities, regexTable, tabPaneOptions, tableModel);
                            }
                        }));
                        regexMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        };
    }

    private JMenuItem createEditRegexMenuItem(List<RegexEntity> regexEntities,
                                              JTable optionsRegexTable,
                                              JPanel tabPaneOptions,
                                              RegexListTableModel tableModel) {
        JMenuItem btnEditRegex = new JMenuItem(getLocaleString("options-list-edit"));
        btnEditRegex.setEnabled(false);
        btnEditRegex.addActionListener(actionEvent -> {
            editSelectedRegex(regexEntities, optionsRegexTable, tabPaneOptions, tableModel);
        });
        optionsRegexTable.getSelectionModel().addListSelectionListener(event -> {
            int viewRow = optionsRegexTable.getSelectedRow();
            btnEditRegex.setEnabled(!event.getValueIsAdjusting() && viewRow >= 0);
        });
        return btnEditRegex;
    }

    /**
     * Open the edit regex dialog of the selected regex.
     *
     * @param regexEntities
     * @param optionsRegexTable
     * @param tabPaneOptions
     * @param tableModel
     */
    private void editSelectedRegex(List<RegexEntity> regexEntities,
                                   JTable optionsRegexTable,
                                   JPanel tabPaneOptions,
                                   RegexListTableModel tableModel) {
        int rowIndex;
        int realRow;

        rowIndex = optionsRegexTable.getSelectedRow();
        if (rowIndex == -1) return;
        realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);

        RegexEntity previousRegex = regexEntities.get(realRow);
        RegexEditDialog dialog = new RegexEditDialog(previousRegex);
        if (!dialog.showDialog(tabPaneOptions, getLocaleString("options-list-edit-dialogTitle"))) return;

        RegexEntity newRegex = dialog.getRegexEntity();
        if (newRegex.getRegex().isEmpty() && newRegex.getDescription().isEmpty()) return;
        if (previousRegex.equals(newRegex)) return;

        regexEntities.set(realRow, newRegex);

        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableRowsUpdated(realRow, realRow);
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
    }

    private JMenuItem createDeleteRegexMenuItem(List<RegexEntity> regexEntities,
                                                JTable optionsRegexTable,
                                                JPanel tabPaneOptions,
                                                RegexListTableModel tableModel) {
        JMenuItem btnDeleteRegex = new JMenuItem(getLocaleString("options-list-delete"));
        btnDeleteRegex.setEnabled(false);
        btnDeleteRegex.addActionListener(actionEvent -> {
            deleteSelectedRegex(regexEntities, optionsRegexTable, tabPaneOptions, tableModel);
        });
        optionsRegexTable.getSelectionModel().addListSelectionListener(event -> {
            int viewRow = optionsRegexTable.getSelectedRow();
            btnDeleteRegex.setEnabled(!event.getValueIsAdjusting() && viewRow >= 0);
        });
        return btnDeleteRegex;
    }

    /**
     * Delete the selected regex from the table.
     *
     * @param regexEntities
     * @param optionsRegexTable
     * @param tabPaneOptions
     * @param tableModel
     */
    private void deleteSelectedRegex(List<RegexEntity> regexEntities,
                                     JTable optionsRegexTable,
                                     JPanel tabPaneOptions,
                                     RegexListTableModel tableModel) {
        int rowIndex = optionsRegexTable.getSelectedRow();
        if (rowIndex == -1) return;
        int realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);
        regexEntities.remove(realRow);

        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableRowsDeleted(realRow, realRow);
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
    }

    private JMenuItem createNewRegexMenuItem(List<RegexEntity> regexEntities,
                                             JPanel tabPaneOptions,
                                             RegexListTableModel tableModel) {
        JMenuItem btnNewRegex = new JMenuItem(getLocaleString("options-list-new"));
        btnNewRegex.addActionListener(actionEvent -> {
            RegexEditDialog dialog = new RegexEditDialog();
            if (!dialog.showDialog(tabPaneOptions, getLocaleString("options-list-new-dialogTitle"))) return;

            RegexEntity newRegex = dialog.getRegexEntity();
            if (newRegex.getRegex().isEmpty() && newRegex.getDescription().isEmpty()) return;

            int row = regexEntities.size();
            regexEntities.add(newRegex);
            tableModel.fireTableRowsInserted(row, row);
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnNewRegex;
    }

    private JMenuItem createListSaveMenuItem(List<RegexEntity> regexEntities) {
        JMenuItem menuItem = new JMenuItem(getLocaleString("options-list-save"));
        List<String> options = Arrays.asList("JSON", "CSV");
        menuItem.addActionListener(actionEvent -> {
            String filepath = SwingUtils.selectFile(options, false);
            FileUtils.exportRegexListToFile(filepath, regexEntities);
        });

        return menuItem;
    }

    private JMenuItem createListOpenMenuItem(List<RegexEntity> regexEntities,
                                             JPanel tabPaneOptions,
                                             RegexListTableModel tableModel) {
        List<String> options = Arrays.asList("JSON", "CSV");
        JMenuItem menuItem = new JMenuItem(getLocaleString("options-list-open"));
        menuItem.addActionListener(actionEvent -> {
            StringBuilder message = new StringBuilder();
            String filepath = SwingUtils.selectFile(options, true);

            try {
                FileUtils.importRegexListFromFile(filepath, regexEntities)
                        .stream()
                        .map(entity -> String.format("%s - %s\n", entity.getDescription(), entity.getRegex()))
                        .forEach(message::append);
                SwingUtilities.invokeLater(() -> SwingUtils.showMessageDialog(
                        getLocaleString("options-list-open-alreadyPresentTitle"),
                        getLocaleString("options-list-open-alreadyPresentWarn"),
                        message.toString()));
            } catch (Exception exception) {
                SwingUtilities.invokeLater(() -> SwingUtils.showMessageDialog(
                        getLocaleString("options-list-open-importErrorTitle"),
                        getLocaleString("options-list-open-importErrorWarn"),
                        exception.toString()));
            }

            tableModel.fireTableDataChanged();
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });

        return menuItem;
    }

    private JMenuItem createListClearMenuItem(List<RegexEntity> regexEntities,
                                              JPanel tabPaneOptions,
                                              RegexListTableModel tableModel) {
        JMenuItem btnClearRegex = new JMenuItem(getLocaleString("options-list-clear"));
        btnClearRegex.addActionListener(actionEvent -> {
            int dialogRes = JOptionPane.showConfirmDialog(
                    null,
                    getLocaleString("options-list-clear-message"),
                    getLocaleString("options-list-clear-title"),
                    JOptionPane.YES_NO_OPTION);
            if (dialogRes != JOptionPane.OK_OPTION) return;

            if (!regexEntities.isEmpty()) {
                regexEntities.subList(0, regexEntities.size()).clear();
                tableModel.fireTableDataChanged();
                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            }
        });
        return btnClearRegex;
    }

    private JMenuItem createListResetMenuItem(List<RegexEntity> regexEntities,
                                              Supplier<List<RegexEntity>> resetRegexSeeder,
                                              JPanel tabPaneOptions,
                                              RegexListTableModel tableModel) {
        JMenuItem btnResetRegex = new JMenuItem(getLocaleString("options-list-reset"));
        btnResetRegex.addActionListener(actionEvent -> {
            int dialogRes = JOptionPane.showConfirmDialog(
                    null,
                    getLocaleString("options-list-reset-message"),
                    getLocaleString("options-list-reset-title"),
                    JOptionPane.YES_NO_OPTION);
            if (dialogRes != JOptionPane.OK_OPTION) return;

            if (!regexEntities.isEmpty()) {
                regexEntities.subList(0, regexEntities.size()).clear();
            }

            regexEntities.clear();
            regexEntities.addAll(resetRegexSeeder.get());

            tableModel.fireTableDataChanged();
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnResetRegex;
    }

    private JButton createSetEnabledButton(List<RegexEntity> regexEntities,
                                           boolean isEnabled,
                                           JPanel tabPaneOptions,
                                           RegexListTableModel tableModel) {
        String label = getLocaleString(isEnabled ? "options-list-enableAll" : "options-list-disableAll");
        JButton btnSetAllEnabled = new JButton(label);
        btnSetAllEnabled.addActionListener(actionEvent -> {
            regexEntities.forEach(regex -> regex.setActive(isEnabled));

            tableModel.fireTableDataChanged();
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnSetAllEnabled;
    }
}
