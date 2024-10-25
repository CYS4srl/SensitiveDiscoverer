package com.cys4.sensitivediscoverer.ui.tab;

import com.cys4.sensitivediscoverer.utils.Utils;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.util.Objects;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

public class AboutTab implements ApplicationTab {
    private static final String TAB_NAME = getLocaleString("tab-about");
    private final JPanel panel;


    public AboutTab() {
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
     * About panel hierarchy:
     * <pre>
     * box [BorderLayout]
     * +--boxCenter [GridBagLayout]
     *    +--main [GridBagLayout] (centered with spacers)
     *       +--header [GridBagLayout]
     *       +--content [GridBagLayout]
     *       +--footer [GridBagLayout]
     * </pre>
     *
     * @return The panel for the About Tab
     */
    private JPanel createPanel() {
        JPanel box;
        JPanel main;
        JPanel boxCenter;
        JPanel header;
        JPanel content;
        JPanel footer;
        GridBagConstraints gbc;

        Font titleFont = new Font("Lucida Grande", Font.BOLD, 36);
        Font subtitleFont = new Font("Lucida Grande", Font.ITALIC, 24);
        Font bodyFont = new Font("Lucida Grande", Font.PLAIN, 18);

        // ------- BOX -------
        box = new JPanel();
        box.setLayout(new BorderLayout(0, 0));
        boxCenter = new JPanel();
        boxCenter.setLayout(new GridBagLayout());
        box.add(boxCenter, BorderLayout.CENTER);
        main = new JPanel();
        main.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        boxCenter.add(main, gbc);
        final JPanel spacerBottom = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weighty = 2.0;
        gbc.fill = GridBagConstraints.VERTICAL;
        boxCenter.add(spacerBottom, gbc);
        final JPanel spacerTop = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.VERTICAL;
        boxCenter.add(spacerTop, gbc);
        final JPanel spacerRight = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        boxCenter.add(spacerRight, gbc);
        final JPanel spacerLeft = new JPanel();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        boxCenter.add(spacerLeft, gbc);
        // -----------------------


        // ------- HEADER -------
        header = new JPanel();
        header.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 35, 0);
        main.add(header, gbc);
        JLabel title = new JLabel();
        title.setFont(titleFont);
        title.setHorizontalAlignment(0);
        title.setText(getLocaleString("about-header-label"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 2.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        header.add(title, gbc);
        JLabel subtitle = new JLabel();
        subtitle.setFont(subtitleFont);
        subtitle.setHorizontalAlignment(0);
        subtitle.setText(getLocaleString("about-subheader-label"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 2.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(3, 0, 0, 0);
        header.add(subtitle, gbc);
        JLabel titleSeparator = new JLabel();
        titleSeparator.setHorizontalAlignment(0);
        titleSeparator.setText("_________________________________");
        titleSeparator.setVerticalTextPosition(0);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 2.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 0, 0, 0);
        header.add(titleSeparator, gbc);
        // -----------------------


        // ------- CONTENT -------
        content = new JPanel();
        content.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 20, 0, 20);
        main.add(content, gbc);
        JLabel authorLabel = new JLabel();
        authorLabel.setFont(bodyFont);
        authorLabel.setText(getLocaleString("about-author-label"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 5);
        content.add(authorLabel, gbc);
        JLabel authorValueLabel = new JLabel();
        authorValueLabel.setFont(bodyFont);
        authorValueLabel.setHorizontalAlignment(2);
        authorValueLabel.setText("CYS4");
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        content.add(authorValueLabel, gbc);
        JLabel versionLabel = new JLabel();
        versionLabel.setFont(bodyFont);
        versionLabel.setHorizontalAlignment(4);
        versionLabel.setText(getLocaleString("about-version-label"));
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 5);
        content.add(versionLabel, gbc);
        JLabel versionValueLabel = new JLabel();
        versionValueLabel.setFont(bodyFont);
        versionValueLabel.setText(Utils.getExtensionVersion());
        gbc = new GridBagConstraints();
        gbc.gridx = 3;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        content.add(versionValueLabel, gbc);
        JLabel linksDescription1 = new JLabel();
        linksDescription1.setFont(bodyFont);
        linksDescription1.setHorizontalAlignment(0);
        linksDescription1.setText(getLocaleString("about-support-label-1"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(100, 0, 0, 0);
        content.add(linksDescription1, gbc);
        JLabel linksDescription2 = new JLabel();
        linksDescription2.setFont(bodyFont);
        linksDescription2.setHorizontalAlignment(0);
        linksDescription2.setText(getLocaleString("about-support-label-2"));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 0, 20, 0);
        content.add(linksDescription2, gbc);
        JButton CYS4SiteButton = new JButton();
        CYS4SiteButton.setText(getLocaleString("about-website-button"));
        CYS4SiteButton.setPreferredSize(new Dimension(-1, 45));
        CYS4SiteButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://cys4.com"));
            } catch (Exception ignored) {
            }
        });
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 4, 4);
        content.add(CYS4SiteButton, gbc);
        JButton CYS4BlogButton = new JButton();
        CYS4BlogButton.setText(getLocaleString("about-blog-button"));
        CYS4BlogButton.setPreferredSize(new Dimension(-1, 45));
        CYS4BlogButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://blog.cys4.com"));
            } catch (Exception ignored) {
            }
        });
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 4, 4, 0);
        content.add(CYS4BlogButton, gbc);
        JButton githubPageButton = new JButton();
        githubPageButton.setText(getLocaleString("about-github-button"));
        githubPageButton.setPreferredSize(new Dimension(-1, 45));
        githubPageButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://github.com/CYS4srl/CYS4-SensitiveDiscoverer"));
            } catch (Exception ignored) {
            }
        });
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 0, 0, 0);
        content.add(githubPageButton, gbc);
        // -----------------------


        // ------- FOOTER -------
        footer = new JPanel();
        footer.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(15, 0, 0, 0);
        main.add(footer, gbc);
        JLabel footerIcon = new JLabel();
        try {
            BufferedImage logoImage = ImageIO.read(Objects.requireNonNull(Utils.getResourceAsStream("logo.png")));
            footerIcon.setIcon(new ImageIcon(logoImage.getScaledInstance(400, -1, Image.SCALE_DEFAULT)));
            footerIcon.setText("");
        } catch (Exception ignored) {
        }
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        footer.add(footerIcon, gbc);
        // -----------------------

        return box;
    }
}
