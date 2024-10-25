package com.cys4.sensitivediscoverer.ui.table;

import com.cys4.sensitivediscoverer.model.RegexEntity;

import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.util.List;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

public class RegexListTableModel extends AbstractTableModel {

    private final List<RegexEntity> regexList;

    public RegexListTableModel(List<RegexEntity> regexList) {
        this.regexList = regexList;
    }

    @Override
    public int getRowCount() {
        return regexList.size();
    }

    @Override
    public int getColumnCount() {
        return Column.getSize();
    }

    @Override
    public String getColumnName(int columnIndex) {
        return getLocaleString(Column.getById(columnIndex).localeKey);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return Column.getById(columnIndex).columnType;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return Column.getById(column).editable;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RegexEntity regexEntry = regexList.get(rowIndex);

        return switch (Column.getById(columnIndex)) {
            case ACTIVE -> regexEntry.isActive();
            //TODO: evaluate if there's a better way to display the refinerRegex.
            case REGEX -> regexEntry.getRefinerRegex().orElse("") + regexEntry.getRegex();
            case DESCRIPTION -> regexEntry.getDescription();
            case SECTIONS -> regexEntry.getSectionsHumanReadable();
        };
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        RegexEntity regexEntry = regexList.get(rowIndex);
        regexEntry.setActive((Boolean) value);
        SwingUtilities.invokeLater(() -> fireTableCellUpdated(rowIndex, columnIndex));
    }

    /**
     * Enum representing the columns of the table model for regex lists
     */
    public enum Column {
        ACTIVE("common-active", true, Boolean.class),
        REGEX("common-regex", false, String.class),
        DESCRIPTION("common-description", false, String.class),
        SECTIONS("common-sections", false, String.class);

        private static final List<Column> columns = List.of(ACTIVE, DESCRIPTION, REGEX, SECTIONS);

        private final String localeKey;
        private final boolean editable;
        private final Class<?> columnType;

        Column(String localeKey, boolean editable, Class<?> columnType) {
            this.localeKey = localeKey;
            this.editable = editable;
            this.columnType = columnType;
        }

        public static Column getById(int index) {
            return columns.get(index);
        }

        /**
         * Returns the number of elements in this enum
         *
         * @return the number of elements in this enum
         */
        public static int getSize() {
            return columns.size();
        }
    }
}
