package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.MainUI;
import org.apache.commons.io.FilenameUtils;

import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.util.List;
import java.util.Objects;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

/**
 * Utils to help with Swing related functionalities
 */
public class SwingUtils {

    /**
     * Asserts that the call to this method is done inside the Swing Event Dispatch Thread.
     *
     * @throws RuntimeException If the method is not called withing the Swing EDT.
     */
    public static void assertIsEDT() throws RuntimeException {
        if (!SwingUtilities.isEventDispatchThread())
            throw new RuntimeException("method must be called on EDT");
    }

    /**
     * Shows an information dialog containing a header paragraph, and a message below.
     * If the message is empty, the dialog is not shown.
     *
     * @param title         The dialog window title
     * @param headerMessage The Message to show in the header at the top
     * @param message       The message to show under the headerMessage
     */
    public static void showMessageDialog(String title, String headerMessage, String message) {
        assertIsEDT();
        if (message.isBlank()) return;

        JPanel mainPanel = new JPanel(new BorderLayout(0, 6));
        JLabel headerLabel = new JLabel(headerMessage + ":");
        headerLabel.setFont(MainUI.UIOptions.H1_FONT);
        mainPanel.add(headerLabel, BorderLayout.NORTH);
        JTextArea messageTextArea = new JTextArea(message);
        messageTextArea.setEditable(false);
        mainPanel.add(messageTextArea, BorderLayout.CENTER);

        JDialog alreadyAddedDialog = new JDialog();
        JOptionPane.showMessageDialog(
                alreadyAddedDialog,
                mainPanel,
                title,
                JOptionPane.INFORMATION_MESSAGE);
        alreadyAddedDialog.setVisible(true);
    }

    /**
     * Open JFileChooser to get a file name
     *
     * @param extensionNames the extensions to filter files
     * @param openFile       Set to true if the file should be opened, false if it should be saved
     * @return The filename, or empty string if there was an error
     */
    public static String selectFile(List<String> extensionNames, boolean openFile) {
        assertIsEDT();
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();

        fileChooser.setAcceptAllFileFilterUsed(false);

        extensionNames.stream()
                .map(extensionName -> new FileNameExtensionFilter("." + extensionName, extensionName))
                .forEachOrdered(fileChooser::addChoosableFileFilter);

        fileChooser.setDialogTitle(getLocaleString(openFile
                ? "utils-linesFromFile-importFile"
                : "utils-saveToFile-exportFile"));

        int userSelection = openFile
                ? fileChooser.showOpenDialog(parentFrame)
                : fileChooser.showSaveDialog(parentFrame);

        if (userSelection != JFileChooser.APPROVE_OPTION) return "";

        String exportFilePath = fileChooser.getSelectedFile().getAbsolutePath();
        String selectedExtension = fileChooser.getFileFilter().getDescription().toLowerCase();

        return FilenameUtils.removeExtension(exportFilePath) + selectedExtension;
    }

    /**
     * Recursively disable all components that have a certain property set.
     * When a component with the property specified is found, the component and all the recursive children are enabled to the state specified.
     *
     * @param component parent component
     * @param enabled   enabled state to set
     */
    public static void setEnabledRecursiveComponentsWithProperty(Component component, boolean enabled, String propertyName) {
        assertIsEDT();

        // if component has the property, stop searching this branch and disable everything
        if (component instanceof JComponent jComponent && Objects.nonNull(jComponent.getClientProperty(propertyName))) {
            setEnabledRecursive(component, enabled);
            return;
        }

        // otherwise, continue the search on the children
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursiveComponentsWithProperty(child, enabled, propertyName);
            }
        }
    }

    private static void setEnabledRecursive(Component component, boolean enabled) {
        boolean newState = enabled;

        if (component instanceof JComponent jComponent) {
            if (component.isEnabled() == enabled) {
                // if component is already in the required state, save this information in case the operation needs to be reversed
                jComponent.putClientProperty("previouslyEnabled", enabled);
            } else {
                // set the state to the previous if present, otherwise use the passed one
                Object previousState = jComponent.getClientProperty("previouslyEnabled");
                jComponent.putClientProperty("previouslyEnabled", null);
                newState = (Objects.nonNull(previousState)) ? (boolean) previousState : enabled;
            }
        }

        component.setEnabled(newState);

        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursive(child, enabled);
            }
        }
    }
}
