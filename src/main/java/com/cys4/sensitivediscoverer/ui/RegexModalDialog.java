package com.cys4.sensitivediscoverer.ui;

import burp.SpringUtilities;
import com.cys4.sensitivediscoverer.model.ProxyItemSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;

import javax.swing.*;
import java.awt.*;
import java.util.EnumSet;

import static com.cys4.sensitivediscoverer.controller.Messages.getLocaleString;

/**
 * RegexModalDialog - Dialog for creating and modifying a regex
 */
public class RegexModalDialog {
    private String regex;
    private String description;

    public RegexModalDialog(String regex, String description) {
        this.regex = regex;
        this.description = description;
    }

    public RegexModalDialog() {
        this("", "");
    }

    public RegexModalDialog(RegexEntity defaultRegex) {
        this(defaultRegex.getRegex(), defaultRegex.getDescription());
    }

    /**
     * Show the dialog on the Frame. This call is blocking until the dialog is closed.
     *
     * @param parentComponent the Frame in which the dialog is displayed.
     * @param dialogTitle     the title string for the dialog.
     * @param regexSections   The sections where the regex is applied.
     * @return a boolean indicating if the user confirmed the dialog.
     */
    public boolean showDialog(Component parentComponent, String dialogTitle, EnumSet<ProxyItemSection> regexSections) {
        //Create and populate the panel.
        String[] labels = {
                "%s: ".formatted(getLocaleString("common-regex")),
                "%s: ".formatted(getLocaleString("common-description"))
        };
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        JLabel labelSummary = new JLabel("%s: %s".formatted(
                getLocaleString("options-list-regexModal-matchedSections"),
                regexSections.toString()
        ), JLabel.TRAILING);
        mainPanel.add(labelSummary);

        JPanel inputPanel = new JPanel(new SpringLayout());
        mainPanel.add(inputPanel);

        JLabel labelExpression = new JLabel(labels[0], JLabel.TRAILING);
        inputPanel.add(labelExpression);
        JTextField textFieldRegex = new JTextField(10);
        textFieldRegex.setText(this.regex);
        labelExpression.setLabelFor(textFieldRegex);
        inputPanel.add(textFieldRegex);

        JLabel labelDescription = new JLabel(labels[1], JLabel.TRAILING);
        inputPanel.add(labelDescription);
        JTextField textFieldDescription = new JTextField(10);
        textFieldDescription.setText(this.description);
        labelDescription.setLabelFor(textFieldDescription);
        inputPanel.add(textFieldDescription);

        //Lay out the panel.
        SpringUtilities.makeCompactGrid(inputPanel,
                labels.length, 2, //rows, cols
                6, 6,        //initX, initY
                6, 6);       //xPad, yPad

        int returnValue = JOptionPane.showConfirmDialog(parentComponent, mainPanel, dialogTitle, JOptionPane.YES_NO_OPTION);
        if (returnValue != JOptionPane.YES_OPTION) return false;
        this.regex = textFieldRegex.getText();
        this.description = textFieldDescription.getText();
        return true;
    }

    public String getRegex() {
        return regex;
    }

    public String getDescription() {
        return description;
    }
}
