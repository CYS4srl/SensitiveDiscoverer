/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.seed;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cys4.controller.Utils;
import cys4.model.JsonRegexEntity;
import cys4.model.ProxyItemSection;
import cys4.model.RegexEntity;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RegexSeeder {
    private static final Gson gson = new Gson();

    private static List<RegexEntity> fill(String[] regexFiles) {
        Type tArrayListRegexEntity = new TypeToken<ArrayList<JsonRegexEntity>>() {}.getType();

        return Stream.of(regexFiles)
            .map(Utils::readResourceFile)
            .filter(Objects::nonNull)
            .<List<JsonRegexEntity>>map(regex_file -> gson.fromJson(regex_file, tArrayListRegexEntity))
            .flatMap(Collection::stream)
            .map(element -> new RegexEntity(
                    element.getDescription(),
                    element.getRegex(),
                    element.isActive(),
                    ProxyItemSection.parseSectionsToMatch(element.getSections())))
            .collect(Collectors.toList());
    }

    public static List<RegexEntity> getGeneralRegexes() {
        return fill(new String[]{"regex_general.jsonc", "regex_token.jsonc", "regex_url.jsonc"});
    }

    public static List<RegexEntity> getExtensionRegexes() {
        return fill(new String[]{"extension_general.json"});
    }
}