/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.component;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.cys4.sensitivediscoverer.model.LogEntity;
import com.cys4.sensitivediscoverer.model.LogsTableModel;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.List;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class LogsTableContextMenu extends JPopupMenu {

    public LogsTableContextMenu(LogEntity logEntry,
                                List<LogEntity> logEntries,
                                HttpRequestEditor originalRequestViewer,
                                HttpResponseEditor originalResponseViewer,
                                LogsTableModel logsTableModel,
                                LogsTable logsTable,
                                MontoyaApi burpApi,
                                boolean isAnalysisRunning) {
        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-sendToRepeater")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpApi.repeater().sendToRepeater(logEntry.getRequestResponse().request(), logEntry.getRegexEntity().getDescription());
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-sendToIntruder")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpApi.intruder().sendToIntruder(logEntry.getRequestResponse().request());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu(getLocaleString("logger-ctxMenu-sendToComparer"));
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction(getLocaleString("common-request")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                burpApi.comparer().sendToComparer(logEntry.getRequestResponse().finalRequest().toByteArray());
            }
        });
        sendToComparer.add(comparerRequest);

        JMenuItem comparerResponse = new JMenuItem(new AbstractAction(getLocaleString("common-response")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                burpApi.comparer().sendToComparer(logEntry.getRequestResponse().response().toByteArray());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());
        JMenuItem removeItem = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-removeItem")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logEntries.remove(logEntry);

                int rowIndex = logsTable.getSelectedRow();
                if (rowIndex == -1) return;
                int realRow = logsTable.convertRowIndexToModel(rowIndex);
                logsTableModel.fireTableRowsDeleted(realRow, realRow);

                originalResponseViewer.setResponse(HttpResponse.httpResponse(""));
                originalRequestViewer.setRequest(HttpRequest.httpRequest(""));
            }
        });
        if (isAnalysisRunning) removeItem.setEnabled(false);
        this.add(removeItem);

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyURL")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(logEntry.getRequestResponse().finalRequest().url());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyDescription")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(logEntry.getRegexEntity().getDescription());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyRegex")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(logEntry.getRegexEntity().getRegex());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyMatch")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(logEntry.getMatch());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));
    }
}
