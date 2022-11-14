package burp;

import cys4.ui.MainUI;

public class BurpExtender implements IBurpExtender {
    private MainUI mainUI;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.mainUI = new MainUI(callbacks);
        this.mainUI.initialize();

        callbacks.setExtensionName(mainUI.getNameExtension());

        callbacks.printOutput("Extension loaded successfully!");
    }
}
