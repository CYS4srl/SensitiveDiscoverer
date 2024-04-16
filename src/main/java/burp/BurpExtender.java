package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.cys4.sensitivediscoverer.MainUI;
import com.cys4.sensitivediscoverer.model.UnloadingHandler;
import com.cys4.sensitivediscoverer.utils.Utils;

public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi burpApi) {
        try {
            MainUI mainUI = new MainUI(burpApi);
            mainUI.initializeUI();

            burpApi.extension().setName(mainUI.getExtensionName());

            // enables data to survive reloading of the extension and Burp.
            burpApi.extension().registerUnloadingHandler(
                    new UnloadingHandler(burpApi, mainUI.getScannerOptions(), mainUI.getGeneralRegexList(), mainUI.getExtensionsRegexList()));

            Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
                burpApi.logging().logToError(throwable);
            });

            burpApi.logging().logToOutput("Extension loaded successfully!%nVersion loaded: %s".formatted(Utils.getExtensionVersion()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
