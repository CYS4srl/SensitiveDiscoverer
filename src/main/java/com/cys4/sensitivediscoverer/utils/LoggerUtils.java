package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.LogEntriesManager;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogsTableModel;

import java.util.Optional;
import java.util.function.Consumer;

public class LoggerUtils {
    public static Consumer<LogEntity> createAddLogEntryCallback(LogEntriesManager logEntries, Object logEntriesLock, Optional<LogsTableModel> logsTableModel) {
        return (LogEntity logEntry) -> {
            synchronized (logEntriesLock) {
                int row = logEntries.size();

                if (!logEntries.contains(logEntry)) {
                    logEntries.add(logEntry);
                    logsTableModel.ifPresent(logsTable -> logsTable.addNewRow(row));
                }
            }
        };
    }
}
