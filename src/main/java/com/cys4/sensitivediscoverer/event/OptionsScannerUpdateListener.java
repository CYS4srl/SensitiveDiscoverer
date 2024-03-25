package com.cys4.sensitivediscoverer.event;

import com.cys4.sensitivediscoverer.model.ScannerOptions;

import javax.swing.*;
import java.awt.event.ActionListener;

public abstract class OptionsScannerUpdateListener implements ActionListener {

    protected final ScannerOptions scannerOptions;
    protected JLabel currentValueLabel;
    protected JTextField updatedStatusField;

    public OptionsScannerUpdateListener(ScannerOptions scannerOptions) {
        this.scannerOptions = scannerOptions;
        this.currentValueLabel = null;
        this.updatedStatusField = null;
    }

    public void setCurrentValueLabel(JLabel currentValueLabel) {
        this.currentValueLabel = currentValueLabel;
    }

    public void setUpdatedStatusField(JTextField updatedStatusField) {
        this.updatedStatusField = updatedStatusField;
    }
}
