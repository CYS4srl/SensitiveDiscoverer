/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import com.cys4.sensitivediscoverer.controller.Messages;
import com.cys4.sensitivediscoverer.model.RegexEntity;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class OptionsRegexTableModelUI extends AbstractTableModel {

    private final List<RegexEntity> regexList;

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
            case 0 -> Messages.getString("common-active");
            case 1 -> Messages.getString("common-regex");
            case 2 -> Messages.getString("common-description");
            default -> "";
        };
    }

    public String getColumnNameFormatted(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "active";
            case 1 -> "regex";
            case 2 -> "description";
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
