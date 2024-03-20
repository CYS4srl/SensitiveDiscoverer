/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.RegexListContext;
import com.cys4.sensitivediscoverer.model.RegexListViewerTableModel;
import com.cys4.sensitivediscoverer.utils.FileUtils;
import com.cys4.sensitivediscoverer.utils.SwingUtils;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class RegexListViewer {
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
    public RegexListViewer(String title,
                           String description,
                           List<RegexEntity> regexEntities,
                           Supplier<List<RegexEntity>> resetRegexSeeder) {
        this.panel = createRegexListViewer(title, description, regexEntities, resetRegexSeeder);
    }

    public JPanel getPanel() {
        return panel;
    }

    private JPanel createRegexListViewer(String title,
                                         String description,
                                         List<RegexEntity> regexEntities,
                                         Supplier<List<RegexEntity>> resetRegexSeeder) {
        JPanel container;
        JPanel header;
        JPanel body;

        container = new JPanel();
        container.setLayout(new BorderLayout(0, 0));
        container.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));

        header = createRegexListViewerHeader(title, description);
        container.add(header, BorderLayout.NORTH);

        body = createRegexListViewerBody(regexEntities, resetRegexSeeder);
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

    private JPanel createRegexListViewerHeader(String title, String description) {
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

    private JPanel createRegexListViewerBody(List<RegexEntity> regexEntities, Supplier<List<RegexEntity>> resetRegexSeeder) {
        JPanel container;
        JPanel containerRight;
        JPanel containerCenter;
        GridBagConstraints gbc;

        RegexListContext ctx = new RegexListContext(regexEntities);
        RegexListViewerTableModel tableModel = new RegexListViewerTableModel(ctx.getRegexEntities());

        container = new JPanel(new BorderLayout(0, 0));
        containerCenter = new JPanel(new GridBagLayout());
        container.add(containerCenter, BorderLayout.CENTER);
        containerRight = new JPanel(new GridBagLayout());
        container.add(containerRight, BorderLayout.EAST);

        // table
        JTable regexTable = new RegexListViewerTable(tableModel);
        final JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(regexTable);
        gbc = createGridConstraints(0, 0, 1.0, 1.0, GridBagConstraints.CENTER);
        gbc.fill = GridBagConstraints.BOTH;
        containerCenter.add(scrollPane, gbc);

        // buttons
        JButton enableAllButton = createSetEnabledButton(ctx, true, containerCenter, tableModel);
        containerRight.add(enableAllButton, createButtonGridConstraints(0, 0));
        JButton disableAllButton = createSetEnabledButton(ctx, false, containerCenter, tableModel);
        containerRight.add(disableAllButton, createButtonGridConstraints(0, 1));

        JPopupMenu listMenu = new JPopupMenu();
        listMenu.add(createListClearMenuItem(ctx, containerCenter, tableModel));
        listMenu.add(createListResetMenuItem(ctx, resetRegexSeeder, containerCenter, tableModel));
        listMenu.add(createListOpenMenuItem(ctx, containerCenter, tableModel));
        listMenu.add(createListSaveMenuItem(ctx.getRegexEntities()));
        JToggleButton listButton = new PopupMenuButton(getLocaleString("options-list-listSubmenu"), listMenu);
        containerRight.add(listButton, createButtonGridConstraints(0, 2));

        JPopupMenu regexMenu = new JPopupMenu();
        regexMenu.add(createNewRegexMenuItem(ctx, containerCenter, tableModel));
        regexMenu.add(createEditRegexMenuItem(ctx, regexTable, containerCenter, tableModel));
        regexMenu.add(createDeleteRegexMenuItem(ctx, regexTable, containerCenter, tableModel));
        JToggleButton regexButton = new PopupMenuButton(getLocaleString("options-list-regexSubmenu"), regexMenu);
        containerRight.add(regexButton, createButtonGridConstraints(0, 3));

        return container;
    }

    private JMenuItem createEditRegexMenuItem(RegexListContext ctx,
                                              JTable optionsRegexTable,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel tableModel) {
        JMenuItem btnEditRegex = new JMenuItem(getLocaleString("options-list-edit"));
        btnEditRegex.setEnabled(false);
        btnEditRegex.addActionListener(actionEvent -> {
            boolean ret;
            int rowIndex;
            int realRow;

            rowIndex = optionsRegexTable.getSelectedRow();
            if (rowIndex == -1) return;
            realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);

            RegexEntity previousRegex = ctx.getRegexEntities().get(realRow);
            RegexEditDialog dialog = new RegexEditDialog(previousRegex);
            ret = dialog.showDialog(tabPaneOptions, getLocaleString("options-list-edit-dialogTitle"));
            if (!ret) return;

            RegexEntity newRegex = dialog.getRegexEntity();
            if (newRegex.getRegex().isEmpty() && newRegex.getDescription().isEmpty()) return;
            if (previousRegex.equals(newRegex)) return;

            ctx.getRegexEntities().set(realRow, newRegex);

            tableModel.fireTableRowsUpdated(realRow, realRow);
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        optionsRegexTable.getSelectionModel().addListSelectionListener(event -> {
            int viewRow = optionsRegexTable.getSelectedRow();
            btnEditRegex.setEnabled(!event.getValueIsAdjusting() && viewRow >= 0);
        });
        return btnEditRegex;
    }

    private JMenuItem createDeleteRegexMenuItem(RegexListContext ctx,
                                                JTable optionsRegexTable,
                                                JPanel tabPaneOptions,
                                                RegexListViewerTableModel tableModel) {
        JMenuItem btnDeleteRegex = new JMenuItem(getLocaleString("options-list-delete"));
        btnDeleteRegex.setEnabled(false);
        btnDeleteRegex.addActionListener(actionEvent -> {
            int rowIndex = optionsRegexTable.getSelectedRow();
            if (rowIndex == -1) return;
            int realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);
            ctx.getRegexEntities().remove(realRow);

            tableModel.fireTableRowsDeleted(realRow, realRow);

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        optionsRegexTable.getSelectionModel().addListSelectionListener(event -> {
            int viewRow = optionsRegexTable.getSelectedRow();
            btnDeleteRegex.setEnabled(!event.getValueIsAdjusting() && viewRow >= 0);
        });
        return btnDeleteRegex;
    }

    private JMenuItem createNewRegexMenuItem(RegexListContext ctx,
                                             JPanel tabPaneOptions,
                                             RegexListViewerTableModel tableModel) {
        JMenuItem btnNewRegex = new JMenuItem(getLocaleString("options-list-new"));
        btnNewRegex.addActionListener(actionEvent -> {
            boolean ret;

            RegexEditDialog dialog = new RegexEditDialog();
            ret = dialog.showDialog(tabPaneOptions, getLocaleString("options-list-new-dialogTitle"));
            if (!ret) return;

            RegexEntity newRegex = dialog.getRegexEntity();
            if (newRegex.getRegex().isEmpty() && newRegex.getDescription().isEmpty()) return;

            int row = ctx.getRegexEntities().size();
            ctx.getRegexEntities().add(newRegex);
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

            String fileName = SwingUtils.selectFile(options, false);

            if (fileName.toUpperCase().endsWith("JSON")) {
                FileUtils.exportRegexListToJSON(fileName, regexEntities);
            } else if (fileName.toUpperCase().endsWith("CSV")) {
                FileUtils.exportRegexListToCSV(fileName, regexEntities);
            }
        });

        return menuItem;
    }

    private JMenuItem createListOpenMenuItem(RegexListContext ctx,
                                             JPanel tabPaneOptions,
                                             RegexListViewerTableModel tableModel) {
        List<String> options = Arrays.asList("JSON", "CSV");
        JMenuItem menuItem = new JMenuItem(getLocaleString("options-list-open"));
        menuItem.addActionListener(actionEvent -> {

            String fileName = SwingUtils.selectFile(options, true);

            if (fileName.toUpperCase().endsWith("JSON")) {
                FileUtils.importRegexListFromJSON(fileName, ctx);
            } else if (fileName.toUpperCase().endsWith("CSV")) {
                FileUtils.importRegexListFromCSV(fileName, ctx);
            }

            tableModel.fireTableDataChanged();
            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });

        return menuItem;
    }

    private JMenuItem createListClearMenuItem(RegexListContext ctx,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel tableModel) {
        JMenuItem btnClearRegex = new JMenuItem(getLocaleString("options-list-clear"));
        btnClearRegex.addActionListener(actionEvent -> {
            int dialogRes = JOptionPane.showConfirmDialog(
                    null,
                    getLocaleString("options-list-clear-message"),
                    getLocaleString("options-list-clear-title"),
                    JOptionPane.OK_CANCEL_OPTION);
            if (dialogRes != JOptionPane.OK_OPTION) return;

            if (!ctx.getRegexEntities().isEmpty()) {
                ctx.getRegexEntities().subList(0, ctx.getRegexEntities().size()).clear();
                tableModel.fireTableDataChanged();

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            }
        });
        return btnClearRegex;
    }

    private JMenuItem createListResetMenuItem(RegexListContext ctx,
                                              Supplier<List<RegexEntity>> resetRegexSeeder,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel tableModel) {
        JMenuItem btnResetRegex = new JMenuItem(getLocaleString("options-list-reset"));
        btnResetRegex.addActionListener(actionEvent -> {
            int dialogRes = JOptionPane.showConfirmDialog(
                    null,
                    getLocaleString("options-list-reset-message"),
                    getLocaleString("options-list-reset-title"),
                    JOptionPane.OK_CANCEL_OPTION);
            if (dialogRes != JOptionPane.OK_OPTION) return;

            if (!ctx.getRegexEntities().isEmpty()) {
                ctx.getRegexEntities().subList(0, ctx.getRegexEntities().size()).clear();
            }

            ctx.getRegexEntities().clear();
            ctx.getRegexEntities().addAll(resetRegexSeeder.get());
            tableModel.fireTableDataChanged();

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnResetRegex;
    }

    private JButton createSetEnabledButton(RegexListContext ctx,
                                           boolean isEnabled,
                                           JPanel tabPaneOptions,
                                           RegexListViewerTableModel tableModel) {
        String label = getLocaleString(isEnabled ? "options-list-enableAll" : "options-list-disableAll");
        JButton btnSetAllEnabled = new JButton(label);
        btnSetAllEnabled.addActionListener(actionEvent -> {
            ctx.getRegexEntities().forEach(regex -> regex.setActive(isEnabled));

            tableModel.fireTableDataChanged();

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnSetAllEnabled;
    }
}
