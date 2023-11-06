package com.cys4.sensitivediscoverer.component;

import com.cys4.sensitivediscoverer.model.ProxyItemSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;

import javax.swing.*;
import java.awt.*;
import java.util.EnumSet;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

/**
 * RegexModalDialog - Dialog for creating and modifying a regex
 */
public class RegexEditDialog {
    private String regex;
    private String description;

    public RegexEditDialog(String regex, String description) {
        this.regex = regex;
        this.description = description;
    }

    public RegexEditDialog() {
        this("", "");
    }

    public RegexEditDialog(RegexEntity defaultRegex) {
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
        JPanel mainPanel;
        JPanel contentPanel;
        GridBagConstraints gbc;

        mainPanel = new JPanel(new BorderLayout(0, 12));
        contentPanel = new JPanel(new GridBagLayout());
        mainPanel.add(contentPanel, BorderLayout.CENTER);

        // header
        JLabel labelSummary = new JLabel("%s: %s".formatted(
                getLocaleString("options-list-regexModal-matchedSections"),
                regexSections.toString()
        ));
        mainPanel.add(labelSummary, BorderLayout.NORTH);

        // regex
        JLabel regexLabel = new JLabel("%s: ".formatted(getLocaleString("common-regex")));
        regexLabel.setVerticalTextPosition(SwingConstants.CENTER);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(0, 0, 6, 0);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.VERTICAL;
        contentPanel.add(regexLabel, gbc);
        JTextField regexTextField = new JTextField(10);
        regexTextField.setText(this.regex);
        regexLabel.setLabelFor(regexTextField);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0, 6, 0);
        gbc.fill = GridBagConstraints.BOTH;
        contentPanel.add(regexTextField, gbc);

        // description
        JLabel descriptionLabel = new JLabel("%s: ".formatted(getLocaleString("common-description")));
        descriptionLabel.setVerticalTextPosition(SwingConstants.CENTER);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.VERTICAL;
        contentPanel.add(descriptionLabel, gbc);
        JTextField descriptionTextField = new JTextField(10);
        descriptionTextField.setText(this.description);
        descriptionLabel.setLabelFor(descriptionTextField);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        contentPanel.add(descriptionTextField, gbc);

        int returnValue = JOptionPane.showConfirmDialog(parentComponent, mainPanel, dialogTitle, JOptionPane.YES_NO_OPTION);
        if (returnValue != JOptionPane.YES_OPTION) return false;
        this.regex = regexTextField.getText();
        this.description = descriptionTextField.getText();
        return true;
    }

    public String getRegex() {
        return regex;
    }

    public String getDescription() {
        return description;
    }
}
