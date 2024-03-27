package com.cys4.sensitivediscoverer.model;

import java.util.List;

/**
 * Model for deserialization of regexes files
 */
public class JsonRegexEntity {
    private boolean active;
    private String regex;
    private String refinerRegex;
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

    public String getRefinerRegex() {
        return refinerRegex;
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
