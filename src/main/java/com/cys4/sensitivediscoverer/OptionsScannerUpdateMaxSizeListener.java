package com.cys4.sensitivediscoverer;

import java.awt.event.ActionEvent;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class OptionsScannerUpdateMaxSizeListener extends OptionsScannerUpdateListener {

    public OptionsScannerUpdateMaxSizeListener(MainUI mainUI) {
        super(mainUI);
    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        try {
            int newMaxSizeValue = Integer.parseInt(updatedStatusField.getText());
            if (newMaxSizeValue < 1)
                throw new NumberFormatException(getLocaleString("exception-sizeMustBeGreaterEqualThanOne"));

            this.mainUI.setMaxSizeValueOption(newMaxSizeValue);
            currentValueLabel.setText(String.valueOf(this.mainUI.getMaxSizeValueOption()));
        } catch (NumberFormatException ignored) {
        }
    }
}
