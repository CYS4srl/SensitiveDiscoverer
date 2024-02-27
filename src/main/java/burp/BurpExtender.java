/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.Utils;

public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi burpApi) {
        try {
            MainUI mainUI = new MainUI(burpApi);
            mainUI.initializeUI();

            burpApi.extension().setName(mainUI.getExtensionName());

            burpApi.logging().logToOutput("Extension loaded successfully!%nVersion loaded: %s".formatted(Utils.getExtensionVersion()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
