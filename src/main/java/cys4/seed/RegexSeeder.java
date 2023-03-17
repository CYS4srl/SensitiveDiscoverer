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
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RegexSeeder {
    private static final Gson _gson = new Gson();

    private static List<RegexEntity> fill(String[] regexFiles) {
        Type tArrayListRegexEntity = new TypeToken<ArrayList<JsonRegexEntity>>() {}.getType();

        return Stream.of(regexFiles)
            .<List<JsonRegexEntity>>map(regex_file -> _gson.fromJson(Utils.readResourceFile(regex_file), tArrayListRegexEntity))
            .flatMap(Collection::stream)
            .map(element -> new RegexEntity(
                    element.getDescription(),
                    element.getRegex(),
                    element.isActive(),
                    ProxyItemSection.parseSectionsToMatch(element.getSections())))
            .collect(Collectors.toList());
    }

    public static List<RegexEntity> getGeneralRegexes() {
        return fill(new String[]{"regex_general.json", "regex_token.json", "regex_url.json"});
    }

    public static List<RegexEntity> getExtensionRegexes() {
        return fill(new String[]{"extension_general.json"});
    }
}
