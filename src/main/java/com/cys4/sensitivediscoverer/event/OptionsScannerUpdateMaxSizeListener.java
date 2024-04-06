package com.cys4.sensitivediscoverer.event;

import com.cys4.sensitivediscoverer.model.ScannerOptions;

import javax.swing.*;
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
            SwingUtilities.invokeLater(() -> currentValueLabel.setText(String.valueOf(newMaxSizeValue)));
        } catch (NumberFormatException ignored) {
        }
    }
}
