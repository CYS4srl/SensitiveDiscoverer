package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogEntriesManager;
import com.cys4.sensitivediscoverer.ui.table.LogsTableModel;

import javax.swing.SwingUtilities;
import java.util.function.Consumer;

public class LoggerUtils {
    public static Consumer<LogEntity> createAddLogEntryCallback(LogEntriesManager logEntries,
                                                                Object logEntriesLock,
                                                                LogsTableModel logsTableModel) {
        return (LogEntity logEntry) -> SwingUtilities.invokeLater(() -> {
            synchronized (logEntriesLock) {
                if (!logEntries.contains(logEntry)) {
                    logEntries.add(logEntry);

                    if (logsTableModel == null) return;
                    int row = (logEntries.indexOf(logEntry));
                    logsTableModel.fireTableRowsInserted(row, row);
                }
            }
        });
    }
}
