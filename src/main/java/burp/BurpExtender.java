package burp;

import cys4.ui.MainUI;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        MainUI mainUI = new MainUI(callbacks);
        mainUI.initialize();

        callbacks.setExtensionName(mainUI.getNameExtension());

        callbacks.printOutput("Extension loaded successfully!");
    }
}
