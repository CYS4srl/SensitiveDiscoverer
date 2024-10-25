package com.cys4.sensitivediscoverer.ui.table;

import javax.swing.JTable;
import javax.swing.ListSelectionModel;

/**
 * JTable for viewing a list of regexes
 */
public class RegexListTable extends JTable {
    public RegexListTable(RegexListTableModel regexListTableModel) {
        super(regexListTableModel);
        this.setAutoCreateRowSorter(true);
        this.setFillsViewportHeight(true);
        this.setRowSelectionAllowed(true);
        this.setColumnSelectionAllowed(false);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.getColumnModel().getColumn(0).setMinWidth(80);
        this.getColumnModel().getColumn(0).setMaxWidth(80);
        this.getColumnModel().getColumn(0).setPreferredWidth(80);
    }
}
