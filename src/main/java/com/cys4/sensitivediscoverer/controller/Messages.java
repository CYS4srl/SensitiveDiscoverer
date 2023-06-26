package com.cys4.sensitivediscoverer.controller;

import java.util.Locale;
import java.util.ResourceBundle;

public class Messages {
    private static final String RB_BUNDLE="TextUI";
    private static final String LOCALE_LANGUAGE="en";
    private static final String LOCALE_COUNTRY="US";
    private static final ResourceBundle resourceBundle = ResourceBundle.getBundle(RB_BUNDLE, new Locale(LOCALE_LANGUAGE, LOCALE_COUNTRY));

    public static String getLocaleString(String key) {
        return resourceBundle.getString(key);
    }
}
