/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import javax.swing.table.AbstractTableModel;
import java.util.List;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class LogsTableModel extends AbstractTableModel {

    // get the reference of the array of entries
    private final List<LogEntity> logEntries;

    public LogsTableModel(List<LogEntity> logEntries) {
        this.logEntries = logEntries;
    }

    @Override
    public int getRowCount() {
        return logEntries.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> getLocaleString("common-url");
            case 1 -> getLocaleString("common-regex");
            case 2 -> getLocaleString("common-match");
            default -> "";
        };
    }

    public String getColumnNameFormatted(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "url";
            case 1 -> "regex";
            case 2 -> "match";
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntity logEntity = logEntries.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> logEntity.getRequestUrl();
            case 1 -> logEntity.getRegexEntity().getDescription() + " - " + logEntity.getRegexEntity().getRegex();
            case 2 -> logEntity.getMatch();
            default -> "";
        };
    }

    public void addNewRow(int row) {
        fireTableRowsInserted(row, row);
    }

    public void clear() {
        fireTableDataChanged();
    }
}
