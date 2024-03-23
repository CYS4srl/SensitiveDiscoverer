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
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntity logEntity = logEntries.get(rowIndex);

        return switch (Column.getById(columnIndex)) {
            case URL -> logEntity.getRequestUrl();
            case REGEX -> logEntity.getRegexEntity().getDescription();
            case SECTION -> logEntity.getMatchedSection();
            case MATCH -> logEntity.getMatch();
        };
    }

    public void addNewRow(int row) {
        fireTableRowsInserted(row, row);
    }

    public void clear() {
        fireTableDataChanged();
    }

    /**
     * Enum representing the columns of the table model for logs
     */
    public enum Column {
        URL("common-url", "url", String.class),
        REGEX("common-regex", "regex", String.class),
        SECTION("common-section", "section", String.class),
        MATCH("common-match", "match", String.class);

        private static final List<Column> columns = List.of(REGEX, MATCH, URL, SECTION);

        private final String localeKey;
        private final String formattedName;
        private final Class<?> columnType;

        Column(String localeKey, String formattedName, Class<?> columnType) {
            this.localeKey = localeKey;
            this.formattedName = formattedName;
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

        public String getNameFormatted() {
            return formattedName;
        }

        public int getIndex() {
            return columns.indexOf(this);
        }
    }
}
