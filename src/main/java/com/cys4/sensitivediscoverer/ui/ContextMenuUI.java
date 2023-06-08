/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
import com.cys4.sensitivediscoverer.model.LogEntity;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.List;

public class ContextMenuUI extends JPopupMenu {

    public ContextMenuUI(LogEntity le, List<LogEntity> logEntries, ITextEditor originalRequestViewer, ITextEditor originalResponseViewer, LogTableEntriesUI logTableEntriesUI, LogTableEntryUI logTableEntryUI, IBurpExtenderCallbacks callbacks) {
        // populate the menu
        String urlLog = le.getURL().toString();
        if (urlLog.length() > 50) urlLog = urlLog.substring(0, 47) + "...";
        this.add(new JMenuItem(urlLog));
        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send to Repeater") {
            @Override
            public void actionPerformed(ActionEvent e) {
                callbacks.sendToRepeater(le.getHost(), le.getPort(), le.isSSL(), le.getRequestResponse().getRequest(), "regext");
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send to Intruder") {
            @Override
            public void actionPerformed(ActionEvent e) {
                callbacks.sendToIntruder(le.getHost(), le.getPort(), le.isSSL(), le.getRequestResponse().getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Request") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                callbacks.sendToComparer(le.getRequestResponse().getRequest());
            }
        });
        sendToComparer.add(comparerRequest);

        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Response") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                callbacks.sendToComparer(le.getRequestResponse().getResponse());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());
        JMenuItem removeItem = new JMenuItem(new AbstractAction("Remove Item") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logEntries.remove(le);

                int rowIndex = logTableEntryUI.getSelectedRow();
                int realRow = logTableEntryUI.convertRowIndexToModel(rowIndex);
                logTableEntriesUI.fireTableRowsDeleted(realRow, realRow);

                originalResponseViewer.setText(new byte[0]);
                originalRequestViewer.setText(new byte[0]);
            }
        });
        this.add(removeItem);


        this.add(new JMenuItem(new AbstractAction("Copy URL") {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection stsel = new StringSelection(le.getURL().toString());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(stsel, stsel);
            }
        }));

        this.add(new JMenuItem(new AbstractAction("Copy Description") {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection stsel = new StringSelection(le.getDescription());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(stsel, stsel);
            }
        }));

        this.add(new JMenuItem(new AbstractAction("Copy Regex") {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection stsel = new StringSelection(le.getRegex());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(stsel, stsel);
            }
        }));

        this.add(new JMenuItem(new AbstractAction("Copy Match") {
            @Override
            public void actionPerformed(final ActionEvent e) {
                StringSelection stsel = new StringSelection(le.getMatch());
                Clipboard system = Toolkit.getDefaultToolkit().getSystemClipboard();
                system.setContents(stsel, stsel);
            }
        }));
    }
}
