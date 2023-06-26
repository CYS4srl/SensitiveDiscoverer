package com.cys4.sensitivediscoverer.controller;

import com.cys4.sensitivediscoverer.scanner.BurpLeaksScanner;
import com.cys4.sensitivediscoverer.ui.MainUI;

import java.awt.event.ActionEvent;

import static com.cys4.sensitivediscoverer.controller.Messages.getLocaleString;

public class OptionsScannerUpdateNumThreadsListener extends OptionsScannerUpdateListener {

    public OptionsScannerUpdateNumThreadsListener(MainUI mainUI) {
        super(mainUI);
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        try {
            int newThreadNumber = Integer.parseInt(updatedStatusField.getText());
            if (newThreadNumber < 1 || newThreadNumber > 128)
                throw new NumberFormatException(getLocaleString("exception-numberNotInTheExpectedRange"));

            BurpLeaksScanner burpLeaksScanner = this.mainUI.getBurpLeaksScanner();
            burpLeaksScanner.setNumThreads(newThreadNumber);
            currentValueLabel.setText(String.valueOf(burpLeaksScanner.getNumThreads()));
            updatedStatusField.setText("");
        } catch (NumberFormatException ignored) {
        }
    }
}
