/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import java.util.List;

/**
 * Model for deserialization of regexes files
 */
public class JsonRegexEntity {
    private boolean active;
    private String regex;
    private String description;
    private List<String> sections;
    private List<String> tests;

    public JsonRegexEntity() {
    }

    public boolean isActive() {
        return active;
    }

    public String getRegex() {
        return regex;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getSections() {
        return sections;
    }

    public List<String> getTests() {
        return tests;
    }
}
