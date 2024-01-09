/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.component;

import burp.ITextEditor;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogsTableModel;

import javax.swing.*;
import java.util.List;
import java.util.Objects;

/**
 * JTable for Viewing Logs
 */
public class LogsTable extends JTable {

    // get the reference of the array of entries
    private final List<LogEntity> logEntries;
    private final ITextEditor requestViewer;
    private final ITextEditor responseViewer;

    public LogsTable(LogsTableModel logsTableModel, List<LogEntity> logEntries, ITextEditor requestViewer, ITextEditor responseViewer) {
        super(logsTableModel);
        this.getColumnModel().getColumn(0).setMinWidth(80);
        this.getColumnModel().getColumn(0).setMaxWidth(80);
        this.getColumnModel().getColumn(0).setPreferredWidth(80);

        this.logEntries = logEntries;
        this.requestViewer = requestViewer;
        this.responseViewer = responseViewer;
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        super.changeSelection(row, col, toggle, extend);
        /*
          show the log entry for the selected row; convertRowIndexToModel is used because otherwise the
          selected row is wrong in case the column is sorted somehow
         */
        int realRow = this.convertRowIndexToModel(row);
        LogEntity logEntry = logEntries.get(realRow);

        byte[] originalRequest = logEntry.getRequestResponse().getRequest();
        byte[] originalResponse = logEntry.getRequestResponse().getResponse();
        updateRequestViewers(originalRequest, originalResponse, logEntry.getMatch());
    }

    public void updateRequestViewers(byte[] request, byte[] response, String search) {
        SwingUtilities.invokeLater(() -> {
            requestViewer.setText(Objects.requireNonNullElseGet(request, () -> new byte[0]));
            requestViewer.setSearchExpression(search);
            responseViewer.setText(Objects.requireNonNullElseGet(response, () -> new byte[0]));
            responseViewer.setSearchExpression(search);
        });
    }
}
