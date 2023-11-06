package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.component.PopupMenuButton;
import com.cys4.sensitivediscoverer.component.RegexEditDialog;
import com.cys4.sensitivediscoverer.component.RegexListViewerTable;
import com.cys4.sensitivediscoverer.model.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.List;
import java.util.*;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class RegexListViewer {
    private final JPanel panel;

    /**
     * Creates a JPanel to view regexes in a table, and to make operations on these regexes.
     * <br><br>
     * The components are mainly a table to display the regexes and some buttons to do operations on the list.
     * The input regexEntities is modified accordingly each time an action is performed.
     *
     * @param regexEntities      The list of regexes that the list keeps track of.
     * @param resetRegexSeeder   default set of regexes when the list is cleared.
     * @param newRegexesSections BurpSuite's Request/Response sections where the regex is applied.
     */
    public RegexListViewer(String title,
                           String description,
                           List<RegexEntity> regexEntities,
                           Supplier<List<RegexEntity>> resetRegexSeeder, EnumSet<ProxyItemSection> newRegexesSections) {
        this.panel = createRegexListViewer(title, description, regexEntities, resetRegexSeeder, newRegexesSections);
    }

    public JPanel getPanel() {
        return panel;
    }

    private JPanel createRegexListViewer(String title,
                                         String description,
                                         List<RegexEntity> regexEntities,
                                         Supplier<List<RegexEntity>> resetRegexSeeder, EnumSet<ProxyItemSection> newRegexesSections) {
        JPanel container;
        JPanel header;
        JPanel body;

        container = new JPanel();
        container.setLayout(new BorderLayout(0, 0));
        container.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));

        header = createRegexListViewerHeader(title, description);
        container.add(header, BorderLayout.NORTH);

        body = createRegexListViewerBody(regexEntities, resetRegexSeeder, newRegexesSections);
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
        titleLabel.setFont(UIOptions.H1_FONT);
        titleLabel.setForeground(UIOptions.ACCENT_COLOR);
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

    private JPanel createRegexListViewerBody(List<RegexEntity> regexEntities,
                                             Supplier<List<RegexEntity>> resetRegexSeeder, EnumSet<ProxyItemSection> newRegexesSections) {
        JPanel container;
        JPanel containerRight;
        JPanel containerCenter;
        GridBagConstraints gbc;

        RegexListContext ctx = new RegexListContext(regexEntities);
        RegexListViewerTableModel modelReg = new RegexListViewerTableModel(ctx.getRegexEntities());

        container = new JPanel(new BorderLayout(0, 0));
        containerCenter = new JPanel(new GridBagLayout());
        container.add(containerCenter, BorderLayout.CENTER);
        containerRight = new JPanel(new GridBagLayout());
        container.add(containerRight, BorderLayout.EAST);

        // table
        JTable regexTable = new RegexListViewerTable(modelReg);
        final JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(regexTable);
        gbc = createGridConstraints(0, 0, 1.0, 1.0, GridBagConstraints.CENTER);
        gbc.fill = GridBagConstraints.BOTH;
        containerCenter.add(scrollPane, gbc);

        // buttons
        JButton enableAllButton = createSetEnabledButton(ctx, true, containerCenter, modelReg);
        containerRight.add(enableAllButton, createButtonGridConstraints(0, 0));
        JButton disableAllButton = createSetEnabledButton(ctx, false, containerCenter, modelReg);
        containerRight.add(disableAllButton, createButtonGridConstraints(0, 1));

        JPopupMenu listMenu = new JPopupMenu();
        listMenu.add(createListClearMenuItem(ctx, containerCenter, modelReg));
        listMenu.add(createListResetMenuItem(ctx, resetRegexSeeder, containerCenter, modelReg));
        listMenu.add(createListOpenMenuItem(ctx, newRegexesSections, containerCenter, modelReg));
        listMenu.add(createListSaveMenuItem(modelReg));
        JToggleButton listButton = new PopupMenuButton(getLocaleString("options-list-listSubmenu"), listMenu);
        containerRight.add(listButton, createButtonGridConstraints(0, 2));

        JPopupMenu regexMenu = new JPopupMenu();
        regexMenu.add(createNewRegexMenuItem(ctx, newRegexesSections, containerCenter, modelReg));
        regexMenu.add(createEditRegexMenuItem(ctx, newRegexesSections, regexTable, containerCenter, modelReg));
        regexMenu.add(createDeleteRegexMenuItem(ctx, regexTable, containerCenter, modelReg));
        JToggleButton regexButton = new PopupMenuButton(getLocaleString("options-list-regexSubmenu"), regexMenu);
        containerRight.add(regexButton, createButtonGridConstraints(0, 3));

        return container;
    }


    private JMenuItem createEditRegexMenuItem(RegexListContext ctx,
                                              EnumSet<ProxyItemSection> newRegexesSections,
                                              JTable optionsRegexTable,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel modelReg) {
        JMenuItem btnEditRegex = new JMenuItem(getLocaleString("options-list-edit"));
        btnEditRegex.setEnabled(false);
        btnEditRegex.addActionListener(actionEvent -> {
            boolean ret;
            int rowIndex;
            int realRow;

            rowIndex = optionsRegexTable.getSelectedRow();
            if (rowIndex == -1) return;
            realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);

            RegexEntity previousEntity = ctx.getRegexEntities().get(realRow);
            RegexEditDialog dialog = new RegexEditDialog(previousEntity);
            ret = dialog.showDialog(tabPaneOptions, getLocaleString("options-list-edit-dialogTitle"), newRegexesSections);
            if (!ret) return;

            String newRegex = dialog.getRegex();
            String newDescription = dialog.getDescription();
            if (newRegex.isEmpty() && newDescription.isEmpty()) return;
            if (previousEntity.getRegex().equals(newRegex) && previousEntity.getDescription().equals(newDescription))
                return;

            ctx.getRegexEntities().set(realRow, new RegexEntity(newDescription, newRegex, true, newRegexesSections));

            modelReg.fireTableRowsUpdated(realRow, realRow);
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
                                                RegexListViewerTableModel modelReg) {
        JMenuItem btnDeleteRegex = new JMenuItem(getLocaleString("options-list-delete"));
        btnDeleteRegex.setEnabled(false);
        btnDeleteRegex.addActionListener(actionEvent -> {
            int rowIndex = optionsRegexTable.getSelectedRow();
            if (rowIndex == -1) return;
            int realRow = optionsRegexTable.convertRowIndexToModel(rowIndex);
            ctx.getRegexEntities().remove(realRow);

            modelReg.fireTableRowsDeleted(realRow, realRow);

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
                                             EnumSet<ProxyItemSection> newRegexesSections,
                                             JPanel tabPaneOptions,
                                             RegexListViewerTableModel modelReg) {
        JMenuItem btnNewRegex = new JMenuItem(getLocaleString("options-list-new"));
        btnNewRegex.addActionListener(actionEvent -> {
            boolean ret;

            RegexEditDialog dialog = new RegexEditDialog();
            ret = dialog.showDialog(tabPaneOptions, getLocaleString("options-list-new-dialogTitle"), newRegexesSections);
            if (!ret) return;

            String newRegex = dialog.getRegex();
            String newDescription = dialog.getDescription();
            if (newRegex.isEmpty() && newDescription.isEmpty()) return;

            int row = ctx.getRegexEntities().size();
            ctx.getRegexEntities().add(new RegexEntity(newDescription, newRegex, true, newRegexesSections));
            modelReg.fireTableRowsInserted(row, row);

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnNewRegex;
    }

    //TODO loses info on sections used
    private JMenuItem createListSaveMenuItem(RegexListViewerTableModel modelReg) {
        JMenuItem menuItem = new JMenuItem(getLocaleString("options-list-save"));
        menuItem.addActionListener(actionEvent -> {
            int dialog = JOptionPane.showOptionDialog(
                    null,
                    getLocaleString("options-list-save-formatDialogMessage"),
                    getLocaleString("options-list-save-formatDialogTitle"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"JSON", "CSV"},
                    null
            );
            if (dialog == 0) {
                List<JsonObject> lines = new ArrayList<>();

                String prop1 = modelReg.getColumnNameFormatted(2);
                String prop2 = modelReg.getColumnNameFormatted(1);

                // values
                for (int i = 0; i < modelReg.getRowCount(); i++) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty(prop1, modelReg.getValueAt(i, 2).toString());
                    obj.addProperty(prop2, modelReg.getValueAt(i, 1).toString());
                    lines.add(obj);
                }

                GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
                Gson gson = builder.create();
                Type tListEntries = new TypeToken<ArrayList<JsonObject>>() {
                }.getType();
                Utils.saveToFile("json", List.of(gson.toJson(lines, tListEntries)));
            } else if (dialog == 1) {
                List<String> lines = new ArrayList<>();

                // header
                lines.add(String.format("\"%s\",\"%s\"",
                        modelReg.getColumnNameFormatted(2),
                        modelReg.getColumnNameFormatted(1)));

                // values
                int rowCount = modelReg.getRowCount();
                for (int i = 0; i < rowCount; i++) {
                    String description = modelReg.getValueAt(i, 2).toString().replaceAll("\"", "\"\"");
                    String regex = modelReg.getValueAt(i, 1).toString().replaceAll("\"", "\"\"");
                    lines.add(String.format("\"%s\",\"%s\"", description, regex));
                }
                Utils.saveToFile("csv", lines);
            }
        });

        return menuItem;
    }

    //TODO loses info on sections used
    private JMenuItem createListOpenMenuItem(RegexListContext ctx,
                                             EnumSet<ProxyItemSection> newRegexesSections,
                                             JPanel tabPaneOptions,
                                             RegexListViewerTableModel modelReg) {
        JMenuItem menuItem = new JMenuItem(getLocaleString("options-list-open"));
        menuItem.addActionListener(actionEvent -> {
            int dialog = JOptionPane.showOptionDialog(
                    null,
                    getLocaleString("options-list-open-formatDialogMessage"),
                    getLocaleString("options-list-open-formatDialogTitle"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"JSON", "CSV"},
                    null
            );
            if (dialog == 0) {
                Gson gson = new Gson();
                StringBuilder alreadyAddedMsg = new StringBuilder();

                List<String> lines = Utils.linesFromFile("json");
                if (Objects.isNull(lines)) return;

                Type tArrayListRegexEntity = new TypeToken<ArrayList<JsonRegexEntity>>() {
                }.getType();
                Stream.of(String.join("", lines))
                        .<List<JsonRegexEntity>>map(regexList -> gson.fromJson(regexList, tArrayListRegexEntity))
                        .filter(Objects::nonNull)
                        .flatMap(Collection::stream)
                        .map(element -> new RegexEntity(
                                element.getDescription(),
                                element.getRegex(),
                                true,
                                newRegexesSections))
                        .forEachOrdered(regexEntity -> {
                            if (!ctx.getRegexEntities().contains(regexEntity)) {
                                ctx.getRegexEntities().add(regexEntity);
                            } else {
                                alreadyAddedMsg
                                        .append(regexEntity.getDescription())
                                        .append(" - ")
                                        .append(regexEntity.getRegex())
                                        .append("\n");
                            }
                        });

                modelReg.fireTableDataChanged();

                if (!(alreadyAddedMsg.toString().isBlank())) {
                    alreadyAddedMsg.insert(0, getLocaleString("options-list-open-alreadyPresentWarn") + '\n');
                    JDialog alreadyAddedDialog = new JDialog();
                    JOptionPane.showMessageDialog(alreadyAddedDialog, alreadyAddedMsg.toString(), getLocaleString("options-list-open-alreadyPresentTitle"), JOptionPane.INFORMATION_MESSAGE);
                    alreadyAddedDialog.setVisible(true);
                }

                tabPaneOptions.validate();
                tabPaneOptions.repaint();

            } else if (dialog == 1) {
                StringBuilder alreadyAddedMsg = new StringBuilder();

                List<String> lines = Utils.linesFromFile("csv");
                if (Objects.isNull(lines)) return;

                lines.forEach(line -> {
                    Matcher matcher = RegexEntity.checkRegexEntityFromCSV(line);
                    if (!matcher.find()) return;

                    String description = matcher.group(1).replaceAll("\"\"", "\"");
                    String regex = matcher.group(2).replaceAll("\"\"", "\"");
                    if (description.equals(modelReg.getColumnNameFormatted(2)) && regex.equals(modelReg.getColumnNameFormatted(1)))
                        return;

                    RegexEntity newRegexEntity = new RegexEntity(
                            description,
                            regex,
                            true,
                            newRegexesSections
                    );

                    if (!ctx.getRegexEntities().contains(newRegexEntity)) {
                        ctx.getRegexEntities().add(newRegexEntity);
                    } else {
                        alreadyAddedMsg
                                .append(newRegexEntity.getDescription())
                                .append(" - ")
                                .append(newRegexEntity.getRegex())
                                .append("\n");
                    }
                });
                modelReg.fireTableDataChanged();

                if (!(alreadyAddedMsg.toString().isBlank())) {
                    alreadyAddedMsg.insert(0, getLocaleString("options-list-open-alreadyPresentWarn") + '\n');
                    JDialog alreadyAddedDialog = new JDialog();
                    JOptionPane.showMessageDialog(alreadyAddedDialog, alreadyAddedMsg.toString(), getLocaleString("options-list-open-alreadyPresentTitle"), JOptionPane.INFORMATION_MESSAGE);
                    alreadyAddedDialog.setVisible(true);
                }

                tabPaneOptions.validate();
                tabPaneOptions.repaint();

            }
        });

        return menuItem;
    }

    private JMenuItem createListClearMenuItem(RegexListContext ctx,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel modelReg) {
        JMenuItem btnClearRegex = new JMenuItem(getLocaleString("options-list-clear"));
        btnClearRegex.addActionListener(actionEvent -> {
            int dialog = JOptionPane.showConfirmDialog(null, getLocaleString("options-list-clear-confirm"));
            if (dialog != JOptionPane.YES_OPTION) return;

            if (!ctx.getRegexEntities().isEmpty()) {
                ctx.getRegexEntities().subList(0, ctx.getRegexEntities().size()).clear();
                modelReg.fireTableDataChanged();

                tabPaneOptions.validate();
                tabPaneOptions.repaint();
            }
        });
        return btnClearRegex;
    }

    private JMenuItem createListResetMenuItem(RegexListContext ctx,
                                              Supplier<List<RegexEntity>> resetRegexSeeder,
                                              JPanel tabPaneOptions,
                                              RegexListViewerTableModel modelReg) {
        JMenuItem btnResetRegex = new JMenuItem(getLocaleString("options-list-reset"));
        btnResetRegex.addActionListener(actionEvent -> {
            int dialog = JOptionPane.showConfirmDialog(null, getLocaleString("options-list-reset-confirm"));
            if (dialog != JOptionPane.YES_OPTION) return;

            if (!ctx.getRegexEntities().isEmpty()) {
                ctx.getRegexEntities().subList(0, ctx.getRegexEntities().size()).clear();
            }

            ctx.getRegexEntities().clear();
            ctx.getRegexEntities().addAll(resetRegexSeeder.get());
            modelReg.fireTableDataChanged();

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnResetRegex;
    }

    private JButton createSetEnabledButton(RegexListContext ctx,
                                           boolean isEnabled,
                                           JPanel tabPaneOptions,
                                           RegexListViewerTableModel modelReg) {
        String label = getLocaleString(isEnabled ? "options-list-enableAll" : "options-list-disableAll");
        JButton btnSetAllEnabled = new JButton(label);
        btnSetAllEnabled.addActionListener(actionEvent -> {
            ctx.getRegexEntities().forEach(regex -> regex.setActive(isEnabled));

            modelReg.fireTableDataChanged();

            tabPaneOptions.validate();
            tabPaneOptions.repaint();
        });
        return btnSetAllEnabled;
    }
}
