package com.cys4.sensitivediscoverer.ui;

import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

/**
 * RegexModalDialog - Dialog for creating and modifying a regex
 */
public class RegexEditDialog {
    private RegexEntity regexEntity;

    /**
     * Create Dialog for a new regex
     */
    public RegexEditDialog() {
        this.regexEntity = null;
    }

    /**
     * Create dialog based on an existing regex
     *
     * @param regex the base regex to edit
     */
    public RegexEditDialog(RegexEntity regex) {
        this.regexEntity = regex;
    }

    public RegexEntity getRegexEntity() {
        return regexEntity;
    }

    /**
     * Show the dialog on the Frame. This call is blocking until the dialog is closed.
     *
     * @param parentComponent the Frame in which the dialog is displayed.
     * @param dialogTitle     the title string for the dialog.
     * @return a boolean indicating if the user confirmed the dialog. If true, this.regexEntity is updated with the new regex;
     */
    public boolean showDialog(Component parentComponent, String dialogTitle) {
        JPanel mainPanel;
        JPanel contentPanel;
        GridBagConstraints gbc;

        mainPanel = new JPanel(new BorderLayout(0, 12));
        contentPanel = new JPanel(new GridBagLayout());
        mainPanel.add(contentPanel, BorderLayout.CENTER);

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
        JTextField regexTextField = new JTextField(12);
        regexLabel.setLabelFor(regexTextField);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 2, 6, 0);
        gbc.fill = GridBagConstraints.BOTH;
        contentPanel.add(regexTextField, gbc);

        // refinerRegex
        JLabel refinerRegexLabel = new JLabel("%s: ".formatted(getLocaleString("common-refinerRegex")));
        refinerRegexLabel.setVerticalTextPosition(SwingConstants.CENTER);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.insets = new Insets(0, 0, 6, 0);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.VERTICAL;
        contentPanel.add(refinerRegexLabel, gbc);
        JTextField refinerRegexTextField = new JTextField(12);
        refinerRegexLabel.setLabelFor(refinerRegexTextField);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 2, 6, 0);
        gbc.fill = GridBagConstraints.BOTH;
        contentPanel.add(refinerRegexTextField, gbc);

        // description
        JLabel descriptionLabel = new JLabel("%s: ".formatted(getLocaleString("common-description")));
        descriptionLabel.setVerticalTextPosition(SwingConstants.CENTER);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.VERTICAL;
        contentPanel.add(descriptionLabel, gbc);
        JTextField descriptionTextField = new JTextField(12);
        descriptionLabel.setLabelFor(descriptionTextField);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 2, 0, 0);
        contentPanel.add(descriptionTextField, gbc);

        // sections
        JLabel sectionsLabel = new JLabel("%s: ".formatted(getLocaleString("common-sections")));
        sectionsLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        sectionsLabel.setVerticalAlignment(SwingConstants.TOP);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 0, 0, 0);
        contentPanel.add(sectionsLabel, gbc);
        JPanel sectionsPanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 2, 0, 0);
        contentPanel.add(sectionsPanel, gbc);
        JCheckBox sectionReqURL = new JCheckBox(getLocaleString("regex-section-reqURL"));
        JCheckBox sectionReqHeaders = new JCheckBox(getLocaleString("regex-section-reqHeaders"));
        JCheckBox sectionReqBody = new JCheckBox(getLocaleString("regex-section-reqBody"));
        JCheckBox sectionResHeaders = new JCheckBox(getLocaleString("regex-section-resHeaders"));
        JCheckBox sectionResBody = new JCheckBox(getLocaleString("regex-section-resBody"));
        sectionsPanel.add(sectionReqURL, getSectionConstraints(0, 0));
        sectionsPanel.add(sectionReqHeaders, getSectionConstraints(0, 1));
        sectionsPanel.add(sectionReqBody, getSectionConstraints(0, 2));
        sectionsPanel.add(sectionResHeaders, getSectionConstraints(1, 0));
        sectionsPanel.add(sectionResBody, getSectionConstraints(1, 1));

        // set defaults
        if (Objects.nonNull(this.regexEntity)) {
            regexTextField.setText(this.regexEntity.getRegex());
            this.regexEntity.getRefinerRegex().ifPresent(refinerRegexTextField::setText);
            descriptionTextField.setText(this.regexEntity.getDescription());

            sectionReqURL.setSelected(this.regexEntity.getSections().contains(HttpSection.REQ_URL));
            sectionReqHeaders.setSelected(this.regexEntity.getSections().contains(HttpSection.REQ_HEADERS));
            sectionReqBody.setSelected(this.regexEntity.getSections().contains(HttpSection.REQ_BODY));
            sectionResHeaders.setSelected(this.regexEntity.getSections().contains(HttpSection.RES_HEADERS));
            sectionResBody.setSelected(this.regexEntity.getSections().contains(HttpSection.RES_BODY));
        } else {
            EnumSet<HttpSection> defaults = HttpSection.getDefault();
            sectionReqURL.setSelected(defaults.contains(HttpSection.REQ_URL));
            sectionReqHeaders.setSelected(defaults.contains(HttpSection.REQ_HEADERS));
            sectionReqBody.setSelected(defaults.contains(HttpSection.REQ_BODY));
            sectionResHeaders.setSelected(defaults.contains(HttpSection.RES_HEADERS));
            sectionResBody.setSelected(defaults.contains(HttpSection.RES_BODY));
        }

        int returnValue = JOptionPane.showConfirmDialog(
                parentComponent,
                mainPanel,
                dialogTitle,
                JOptionPane.OK_CANCEL_OPTION);
        if (returnValue != JOptionPane.OK_OPTION) return false;

        List<HttpSection> sections = Arrays.asList(
                sectionReqURL.getModel().isSelected() ? HttpSection.REQ_URL : null,
                sectionReqHeaders.getModel().isSelected() ? HttpSection.REQ_HEADERS : null,
                sectionReqBody.getModel().isSelected() ? HttpSection.REQ_BODY : null,
                sectionResHeaders.getModel().isSelected() ? HttpSection.RES_HEADERS : null,
                sectionResBody.getModel().isSelected() ? HttpSection.RES_BODY : null);
        this.regexEntity = new RegexEntity(
                descriptionTextField.getText(),
                regexTextField.getText(),
                Objects.isNull(this.regexEntity) || this.regexEntity.isActive(),
                sections.stream().filter(Objects::nonNull).collect(Collectors.toCollection(() -> EnumSet.noneOf(HttpSection.class))),
                refinerRegexTextField.getText()
        );
        return true;
    }

    GridBagConstraints getSectionConstraints(int gridx, int gridy) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gridx;
        gbc.gridy = gridy;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0, 1, 10);
        return gbc;
    }
}
