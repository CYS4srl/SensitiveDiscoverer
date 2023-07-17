package com.cys4.sensitivediscoverer.controller;

import com.cys4.sensitivediscoverer.ui.MainUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public abstract class OptionsScannerUpdateListener implements ActionListener {

    protected JLabel currentValueLabel;
    protected JTextField updatedStatusField;
    protected MainUI mainUI;

    public OptionsScannerUpdateListener(MainUI mainUI) {
        this.currentValueLabel = null;
        this.updatedStatusField = null;
        this.mainUI = mainUI;
    }

    public void setCurrentValueLabel(JLabel currentValueLabel) {
        this.currentValueLabel = currentValueLabel;
    }

    public void setUpdatedStatusField(JTextField updatedStatusField) {
        this.updatedStatusField = updatedStatusField;
    }
}
