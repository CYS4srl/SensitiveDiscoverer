package com.cys4.sensitivediscoverer.ui.table;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogEntriesManager;

import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

/**
 * JTable for Viewing Logs
 */
public class LogsTable extends JTable {

    private final LogEntriesManager logEntries;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;

    public LogsTable(LogsTableModel logsTableModel, LogEntriesManager logEntries, HttpRequestEditor requestViewer, HttpResponseEditor responseViewer) {
        super(logsTableModel);

        this.setAutoCreateRowSorter(false);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.logEntries = logEntries;
        this.requestViewer = requestViewer;
        this.responseViewer = responseViewer;
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        super.changeSelection(row, col, toggle, extend);
        int realRow = this.convertRowIndexToModel(row);
        LogEntity logEntry = logEntries.get(realRow);

        updateRequestViewers(logEntry.getRequest(), logEntry.getResponse(), logEntry.getMatch());
    }

    public void updateRequestViewers(HttpRequest request, HttpResponse response, String search) {
        SwingUtilities.invokeLater(() -> {
            requestViewer.setRequest(request);
            requestViewer.setSearchExpression(search);
            responseViewer.setResponse(response);
            responseViewer.setSearchExpression(search);
        });
    }
}
