/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.component;

import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
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

    public LogsTableContextMenu(LogEntity le,
                                List<LogEntity> logEntries,
                                ITextEditor originalRequestViewer,
                                ITextEditor originalResponseViewer,
                                LogsTableModel logsTableModel,
                                LogsTable logsTable,
                                IBurpExtenderCallbacks callbacks,
                                boolean isAnalysisRunning) {
        // populate the menu
        String urlLog = le.getURL().toString();
        if (urlLog.length() > 50) urlLog = urlLog.substring(0, 47) + "...";
        this.add(new JMenuItem(urlLog));
        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-sendToRepeater")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                callbacks.sendToRepeater(le.getHost(), le.getPort(), le.isSSL(), le.getRequestResponse().getRequest(), "regext");
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-sendToIntruder")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                callbacks.sendToIntruder(le.getHost(), le.getPort(), le.isSSL(), le.getRequestResponse().getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu(getLocaleString("logger-ctxMenu-sendToComparer"));
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction(getLocaleString("common-request")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                callbacks.sendToComparer(le.getRequestResponse().getRequest());
            }
        });
        sendToComparer.add(comparerRequest);

        JMenuItem comparerResponse = new JMenuItem(new AbstractAction(getLocaleString("common-response")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                callbacks.sendToComparer(le.getRequestResponse().getResponse());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());
        JMenuItem removeItem = new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-removeItem")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logEntries.remove(le);

                int rowIndex = logsTable.getSelectedRow();
                if (rowIndex == -1) return;
                int realRow = logsTable.convertRowIndexToModel(rowIndex);
                logsTableModel.fireTableRowsDeleted(realRow, realRow);

                originalResponseViewer.setText(new byte[0]);
                originalRequestViewer.setText(new byte[0]);
            }
        });
        if (isAnalysisRunning) removeItem.setEnabled(false);
        this.add(removeItem);

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyURL")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(le.getURL().toString());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyDescription")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(le.getRegexEntity().getDescription());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyRegex")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(le.getRegexEntity().getRegex());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));

        this.add(new JMenuItem(new AbstractAction(getLocaleString("logger-ctxMenu-copyMatch")) {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection selection = new StringSelection(le.getMatch());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(selection, selection);
            }
        }));
    }
}
