/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.model.ScannerOptions;

import java.awt.event.ActionEvent;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class OptionsScannerUpdateMaxSizeListener extends OptionsScannerUpdateListener {

    public OptionsScannerUpdateMaxSizeListener(ScannerOptions scannerOptions) {
        super(scannerOptions);
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        try {
            int newMaxSizeValue = Integer.parseInt(updatedStatusField.getText());
            if (newMaxSizeValue < 1)
                throw new NumberFormatException(getLocaleString("exception-sizeMustBeGreaterEqualThanOne"));

            scannerOptions.setConfigMaxResponseSize(newMaxSizeValue);
            currentValueLabel.setText(String.valueOf(scannerOptions.getConfigMaxResponseSize()));
        } catch (NumberFormatException ignored) {
        }
    }
}
