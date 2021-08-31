/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.ui;

import cys4.model.LogEntity;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class LogTableEntriesUI extends AbstractTableModel {

    // get the reference of the array of entries
    private List<LogEntity> logEntries;

    public LogTableEntriesUI(List<LogEntity> logEntries) {
        this.logEntries = logEntries;
    }

    //
    // extend AbstractTableModel
    //
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
            case 0 -> "#";
            case 1 -> "URL";
            case 2 -> "Regex";
            case 3 -> "Match";
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
            case 2 -> logEntity.getRegex();
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

