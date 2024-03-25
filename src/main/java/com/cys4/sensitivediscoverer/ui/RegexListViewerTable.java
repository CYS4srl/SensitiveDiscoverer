package com.cys4.sensitivediscoverer.ui;

import com.cys4.sensitivediscoverer.model.RegexListViewerTableModel;

import javax.swing.*;

/**
 * JTable for viewing a list of regexes
 */
public class RegexListViewerTable extends JTable {
    public RegexListViewerTable(RegexListViewerTableModel regexListViewerTableModel) {
        super(regexListViewerTableModel);
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
