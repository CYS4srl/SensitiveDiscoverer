package com.cys4.sensitivediscoverer.ui.table;

import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogEntriesManager;

import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Objects;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

public class LogsTableModel extends AbstractTableModel {

    // get the reference of the array of entries
    private final LogEntriesManager logEntries;

    public LogsTableModel(LogEntriesManager logEntries) {
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
            case SECTION -> logEntity.getMatchedSection().toString();
            case MATCH -> logEntity.getMatch();
        };
    }

    public int getRowHashcode(int rowIndex) {
        LogEntity logEntity = logEntries.get(rowIndex);
        return Objects.hash(
                logEntity.getRequestUrl(),
                logEntity.getRegexEntity().getRegex(),
                logEntity.getMatchedSection().toString(),
                logEntity.getMatch()
        );
    }

    /**
     * Enum representing the columns of the table model for logs
     */
    public enum Column {
        URL("common-url", "url", String.class),
        REGEX("common-description", "description", String.class),
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

        public String getLocaleKey() {
            return localeKey;
        }

        public String getNameFormatted() {
            return formattedName;
        }

        public int getIndex() {
            return columns.indexOf(this);
        }
    }
}
