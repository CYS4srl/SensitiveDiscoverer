package burp;

import com.cys4.sensitivediscoverer.ui.MainUI;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        MainUI mainUI = new MainUI(callbacks);
        mainUI.initialize();

        callbacks.setExtensionName(mainUI.getNameExtension());

        callbacks.printOutput("Extension loaded successfully!%nVersion loaded: %s".formatted(MainUI.getExtensionVersion()));
    }
}
