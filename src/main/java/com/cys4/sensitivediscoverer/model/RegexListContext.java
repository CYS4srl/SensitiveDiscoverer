package com.cys4.sensitivediscoverer.model;

import java.util.List;

public class RegexListContext {

    private final List<RegexEntity> regexEntities;

    public RegexListContext(List<RegexEntity> regexEntities) {
        this.regexEntities = regexEntities;
    }

    public List<RegexEntity> getRegexEntities() {
        return regexEntities;
    }
}
