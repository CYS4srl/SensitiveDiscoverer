package burp;

import cys4.ui.MainUI;
import cys4.model.ExtensionEntity;
import cys4.model.RegexEntity;
import cys4.seed.BurpLeaksSeed;

import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //private List<LogEntity> _lLogEntries = new ArrayList<>();
    private List<RegexEntity> _lRegexes;
    private List<ExtensionEntity> _lExtensions;
    private MainUI mainUI;

    // Implement default constructor
    public BurpExtender()
    {
        _lRegexes = new ArrayList<>();
        _lExtensions = new ArrayList<>();
    }

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {


        // get regexes and extensions
        BurpLeaksSeed bls = new BurpLeaksSeed();

        this._lRegexes = BurpLeaksSeed.getRegex();
        this._lExtensions = BurpLeaksSeed.getExtensions();

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // init the main UI methods
        this.mainUI = new MainUI(_lRegexes, _lExtensions, callbacks);
        this.mainUI.createUI();

        // set our extension name
        callbacks.setExtensionName(mainUI.getNameExtension());

    }
}
