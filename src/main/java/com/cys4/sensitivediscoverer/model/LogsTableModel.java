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
        return 4;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> getLocaleString("logger-table-requestId");
            case 1 -> getLocaleString("common-url");
            case 2 -> getLocaleString("common-regex");
            case 3 -> getLocaleString("common-match");
            default -> "";
        };
    }

    public String getColumnNameFormatted(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "request_id";
            case 1 -> "url";
            case 2 -> "regex";
            case 3 -> "match";
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Integer.class;
        } else {
            return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntity logEntity = logEntries.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> logEntity.getIdRequest();
            case 1 -> logEntity.getURL().toString();
            case 2 -> logEntity.getRegexEntity().getDescription() + " - " + logEntity.getRegexEntity().getRegex();
            case 3 -> logEntity.getMatch();
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
