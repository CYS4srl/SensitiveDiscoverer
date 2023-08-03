package com.cys4.sensitivediscoverer.model;

import java.util.List;

public class RegexContext {

    private final List<RegexEntity> regexEntities;

    public RegexContext(List<RegexEntity> regexEntities) {
        this.regexEntities = regexEntities;
    }

    public List<RegexEntity> getRegexEntities() {
        return regexEntities;
    }
}
