package com.cys4.sensitivediscoverer.ui.tab;

import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.RegexSeeder;
import com.cys4.sensitivediscoverer.event.OptionsScannerUpdateListener;
import com.cys4.sensitivediscoverer.event.OptionsScannerUpdateMaxSizeListener;
import com.cys4.sensitivediscoverer.event.OptionsScannerUpdateNumThreadsListener;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import com.cys4.sensitivediscoverer.ui.RegexListViewer;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class OptionsTab implements ApplicationTab {
    private static final String TAB_NAME = getLocaleString("tab-options");
    private final JPanel panel;
    private final MainUI mainUI;
    private final ScannerOptions scannerOptions;

    public OptionsTab(MainUI mainUI) {
        this.mainUI = mainUI;
        this.scannerOptions = mainUI.getScannerOptions();

        // leave as last call
        this.panel = this.createPanel();
    }

    @Override
    public JPanel getPanel() {
        return this.panel;
    }

    @Override
    public String getTabName() {
        return TAB_NAME;
    }

    /**
     * Options panel hierarchy:
     * <pre>
     * box [BorderLayout]
     * +--boxHeader [GridBagLayout]
     *    +--...configuration panels
     * +--boxCenter [GridBagLayout]
     *    +--general [BorderLayout]
     *    |  +--generalHeader [GridBagLayout]
     *    |  +--generalBody [BorderLayout]
     *    |     +--generalBodyRight [GridBagLayout]
     *    |     +--generalBodyCenter [GridBagLayout]
     *    +--extensions [BorderLayout]
     *       +--extensionsHeader [GridBagLayout]
     *       +--extensionsBody [BorderLayout]
     *          +--extensionsBodyRight [GridBagLayout]
     *          +--extensionsBodyCenter [GridBagLayout]
     * </pre>
     *
     * @return The panel for the Options Tab
     */
    private JPanel createPanel() {
        JPanel box;
        JPanel boxHeader;
        JPanel boxCenter;

        OptionsScannerUpdateListener threadNumListener = new OptionsScannerUpdateNumThreadsListener(scannerOptions);
        OptionsScannerUpdateListener responseSizeListener = new OptionsScannerUpdateMaxSizeListener(scannerOptions);

        boxHeader = new JPanel(new GridBagLayout());
        createConfigurationPanels(boxHeader, threadNumListener, responseSizeListener);

        boxCenter = new JPanel(new GridBagLayout());
        createListsPanels(boxCenter);

        box = new JPanel(new BorderLayout(0, 0));
        box.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        box.add(boxHeader, BorderLayout.NORTH);
        box.add(boxCenter, BorderLayout.CENTER);
        box.putClientProperty("analysisDependent", "1");

        return box;
    }

    private void createListsPanels(JPanel boxCenter) {
        GridBagConstraints gbc;

        RegexListViewer generalList = new RegexListViewer(
                getLocaleString("options-generalList-title"),
                getLocaleString("options-generalList-description"),
                this.mainUI.getGeneralRegexList(),
                RegexSeeder::getGeneralRegexes);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        boxCenter.add(generalList.getPanel(), gbc);

        RegexListViewer extensionsList = new RegexListViewer(
                getLocaleString("options-extensionsList-title"),
                getLocaleString("options-extensionsList-description"),
                this.mainUI.getExtensionsRegexList(),
                RegexSeeder::getExtensionRegexes);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        boxCenter.add(extensionsList.getPanel(), gbc);
    }

    private void createConfigurationPanels(JPanel boxHeader, OptionsScannerUpdateListener threadNumListener, OptionsScannerUpdateListener responseSizeListener) {
        GridBagConstraints gbc;

        final JPanel filterPanel = createConfigurationFilterPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.ipadx = 5;
        gbc.ipady = 5;
        boxHeader.add(filterPanel, gbc);

        final JPanel scannerPanel = createConfigurationScannerPanel(threadNumListener, responseSizeListener);
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.ipadx = 5;
        gbc.ipady = 5;
        gbc.insets = new Insets(0, 20, 0, 0);
        boxHeader.add(scannerPanel, gbc);

        final JPanel spacerLeft = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        boxHeader.add(spacerLeft, gbc);
        final JSeparator middleSeparator = new JSeparator();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 0, 0, 0);
        boxHeader.add(middleSeparator, gbc);
        final JPanel spacerRight = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 3;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        boxHeader.add(spacerRight, gbc);
    }

    private JPanel createConfigurationScannerPanel(OptionsScannerUpdateListener threadNumListener, OptionsScannerUpdateListener responseSizeListener) {
        final JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.gray, 1),
                getLocaleString("options-scanner-title"),
                TitledBorder.LEFT,
                TitledBorder.DEFAULT_POSITION,
                MainUI.UIOptions.H2_FONT,
                MainUI.UIOptions.ACCENT_COLOR
        ));

        createOptionThreadsNumber(panel, threadNumListener);
        createOptionMaxResponseSize(panel, responseSizeListener);

        return panel;
    }

    private JPanel createConfigurationFilterPanel() {
        GridBagConstraints gbc;

        final JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.gray, 1),
                getLocaleString("options-filters-title"),
                TitledBorder.LEFT,
                TitledBorder.DEFAULT_POSITION,
                MainUI.UIOptions.H2_FONT,
                MainUI.UIOptions.ACCENT_COLOR
        ));

        JCheckBox inScopeCheckbox = new JCheckBox();
        inScopeCheckbox.setText(getLocaleString("options-filters-showOnlyInScopeItems"));
        inScopeCheckbox.getModel().setSelected(scannerOptions.isFilterInScopeCheckbox());
        inScopeCheckbox.addActionListener(e -> scannerOptions.setFilterInScopeCheckbox(inScopeCheckbox.getModel().isSelected()));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(inScopeCheckbox, gbc);

        JCheckBox skipMaxSizeCheckbox = new JCheckBox();
        skipMaxSizeCheckbox.setText(getLocaleString("options-filters-skipResponsesOverSetSize"));
        skipMaxSizeCheckbox.getModel().setSelected(scannerOptions.isFilterSkipMaxSizeCheckbox());
        skipMaxSizeCheckbox.addActionListener(e -> scannerOptions.setFilterSkipMaxSizeCheckbox(skipMaxSizeCheckbox.getModel().isSelected()));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(skipMaxSizeCheckbox, gbc);

        JCheckBox skipMediaTypeCheckbox = new JCheckBox();
        skipMediaTypeCheckbox.setText(getLocaleString("options-filters-skipMediaTypeResponses"));
        skipMediaTypeCheckbox.getModel().setSelected(scannerOptions.isFilterSkipMediaTypeCheckbox());
        skipMediaTypeCheckbox.addActionListener(e -> scannerOptions.setFilterSkipMediaTypeCheckbox(skipMediaTypeCheckbox.getModel().isSelected()));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(skipMediaTypeCheckbox, gbc);

        return panel;
    }

    private void createOptionMaxResponseSize(JPanel containerPanel, OptionsScannerUpdateListener updateListener) {
        GridBagConstraints gbc;


        // current value section
        final JPanel currentValuePanel = new JPanel();
        currentValuePanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(12, 2, 0, 2);
        containerPanel.add(currentValuePanel, gbc);

        final JLabel currentDescriptionPanel = new JLabel();
        currentDescriptionPanel.setText(getLocaleString("options-scanner-currentMaxResponseSize"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 5);
        currentValuePanel.add(currentDescriptionPanel, gbc);

        final JLabel currentValueLabel = new JLabel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        currentValuePanel.add(currentValueLabel, gbc);


        // update value section
        final JPanel updateValuePanel = new JPanel();
        updateValuePanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(2, 2, 0, 2);
        containerPanel.add(updateValuePanel, gbc);

        final JLabel updateDescriptionLabel = new JLabel();
        updateDescriptionLabel.setText(getLocaleString("options-scanner-updateMaxResponseSize"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 5);
        updateValuePanel.add(updateDescriptionLabel, gbc);

        final JTextField updateValueField = new JTextField();
        updateValueField.setColumns(8);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 5);
        updateValuePanel.add(updateValueField, gbc);

        final JButton updateValueButton = new JButton();
        updateValueButton.setText(getLocaleString("common-set"));
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        updateValuePanel.add(updateValueButton, gbc);


        // setup values and listener
        currentValueLabel.setText(String.valueOf(scannerOptions.getConfigMaxResponseSize()));
        updateListener.setCurrentValueLabel(currentValueLabel);
        updateListener.setUpdatedStatusField(updateValueField);
        updateValueButton.addActionListener(updateListener);
    }

    private void createOptionThreadsNumber(JPanel containerPanel, OptionsScannerUpdateListener updateListener) {
        GridBagConstraints gbc;


        // current value section
        final JPanel currentValuePanel = new JPanel();
        currentValuePanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(2, 2, 0, 2);
        containerPanel.add(currentValuePanel, gbc);

        final JLabel currentDescriptionLabel = new JLabel();
        currentDescriptionLabel.setText(getLocaleString("options-scanner-currentNumberOfThreads"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 5);
        currentValuePanel.add(currentDescriptionLabel, gbc);

        final JLabel currentValueLabel = new JLabel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        currentValuePanel.add(currentValueLabel, gbc);


        // update value section
        final JPanel updateValuePanel = new JPanel();
        updateValuePanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(2, 2, 0, 2);
        containerPanel.add(updateValuePanel, gbc);

        final JLabel updateDescriptionLabel = new JLabel();
        updateDescriptionLabel.setText("%s (1-128):".formatted(getLocaleString("options-scanner-updateNumberOfThreads")));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 5);
        updateValuePanel.add(updateDescriptionLabel, gbc);

        JTextField updateValueField = new JTextField();
        updateValueField.setColumns(4);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 5);
        updateValuePanel.add(updateValueField, gbc);

        JButton updateValueButton = new JButton();
        updateValueButton.setText(getLocaleString("common-set"));
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        updateValuePanel.add(updateValueButton, gbc);


        // setup values and listener
        currentValueLabel.setText(String.valueOf(scannerOptions.getConfigNumberOfThreads()));
        updateListener.setCurrentValueLabel(currentValueLabel);
        updateListener.setUpdatedStatusField(updateValueField);
        updateValueButton.addActionListener(updateListener);
    }
}
