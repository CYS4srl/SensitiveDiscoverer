/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package burp;

import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.Utils;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        try {
            MainUI mainUI = new MainUI(callbacks);
            mainUI.initialize();

            callbacks.setExtensionName(mainUI.getNameExtension());

            callbacks.printOutput("Extension loaded successfully!%nVersion loaded: %s".formatted(Utils.getExtensionVersion()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
