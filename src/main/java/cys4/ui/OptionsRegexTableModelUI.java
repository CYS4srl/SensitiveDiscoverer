/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.ui;

import cys4.model.RegexEntity;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class OptionsRegexTableModelUI extends AbstractTableModel {

    private List<RegexEntity> regexList;

    public OptionsRegexTableModelUI(List<RegexEntity> regexList) {
        this.regexList = regexList;
    }

    @Override
    public int getRowCount() {
        return regexList.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "Active";
            case 1 -> "Regex";
            case 2 -> "Description";
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RegexEntity regexEntry = regexList.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> regexEntry.isActive();
            case 1 -> regexEntry.getRegex();
            case 2 -> regexEntry.getDescription();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        RegexEntity regexEntry = regexList.get(rowIndex);
        regexEntry.setActive((Boolean) value);
        fireTableCellUpdated(rowIndex, columnIndex);
    }
}