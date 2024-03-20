/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.event;

import com.cys4.sensitivediscoverer.model.ScannerOptions;

import java.awt.event.ActionEvent;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class OptionsScannerUpdateNumThreadsListener extends OptionsScannerUpdateListener {

    public OptionsScannerUpdateNumThreadsListener(ScannerOptions scannerOptions) {
        super(scannerOptions);
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        try {
            int newThreadNumber = Integer.parseInt(updatedStatusField.getText());
            if (newThreadNumber < 1 || newThreadNumber > 128)
                throw new NumberFormatException(getLocaleString("exception-numberNotInTheExpectedRange"));

            scannerOptions.setConfigNumberOfThreads(newThreadNumber);
            currentValueLabel.setText(String.valueOf(scannerOptions.getConfigNumberOfThreads()));
        } catch (NumberFormatException ignored) {
        }
    }
}
