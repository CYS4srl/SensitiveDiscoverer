package com.cys4.sensitivediscoverer.model;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import com.cys4.sensitivediscoverer.utils.Utils;

import java.util.List;

/**
 * Enables data to be stored and accessed from the Burp preference store to survives reloading of the extension and Burp.
 */
public class UnloadingHandler implements ExtensionUnloadingHandler {

    private final MontoyaApi burpApi;
    private final RegexScannerOptions scannerOptions;
    private final List<RegexEntity> regexEntities;
    private final List<RegexEntity> extensionsRegexEntities;

    public UnloadingHandler(MontoyaApi burpApi, RegexScannerOptions scannerOptions, List<RegexEntity> regexEntities, List<RegexEntity> extensionsRegexEntities) {
        this.burpApi = burpApi;
        this.scannerOptions = scannerOptions;
        this.regexEntities = regexEntities;
        this.extensionsRegexEntities = extensionsRegexEntities;
    }

    /**
     * This method is invoked when the extension is unloaded.
     * Save the scanner options, the regex list and the extensions regex list.
     */
    @Override
    public void extensionUnloaded() {
        Utils.saveScannerOptions(this.burpApi, this.scannerOptions);
        Utils.saveRegexList(this.burpApi, this.regexEntities);
        Utils.saveExtensionsRegexList(this.burpApi, this.extensionsRegexEntities);
    }
}
