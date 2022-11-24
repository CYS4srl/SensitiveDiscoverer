/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.ui;

import cys4.model.ExtensionEntity;
import javax.swing.table.AbstractTableModel;
import java.util.List;

public class OptionsExtTableModelUI extends AbstractTableModel {

    private final List<ExtensionEntity> extensionList;

    public OptionsExtTableModelUI(List<ExtensionEntity> extensionList){
        this.extensionList = extensionList;
    }

    @Override
    public int getRowCount() {
        return extensionList.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "Active";
            case 1 -> "Extension";
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
        ExtensionEntity extensionEntry = extensionList.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> extensionEntry.isActive();
            case 1 -> extensionEntry.getRegex();
            case 2 -> extensionEntry.getDescription();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        ExtensionEntity extensionEntry = extensionList.get(rowIndex);
        extensionEntry.setActive((Boolean) value);
        fireTableCellUpdated(rowIndex, columnIndex);
    }
}
