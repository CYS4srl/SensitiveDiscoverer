package com.cys4.sensitivediscoverer;

import java.awt.event.ActionEvent;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

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

            RegexScanner regexScanner = this.mainUI.getRegexScanner();
            regexScanner.setNumThreads(newThreadNumber);
            currentValueLabel.setText(String.valueOf(regexScanner.getNumThreads()));
        } catch (NumberFormatException ignored) {
        }
    }
}
