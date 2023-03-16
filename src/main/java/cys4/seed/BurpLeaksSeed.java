/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.seed;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cys4.controller.Utils;
import cys4.model.RegexEntity;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

public class BurpLeaksSeed {

    private static final List<RegexEntity> general_regexes = new ArrayList<>();
    private static final List<RegexEntity> extensions_regexes = new ArrayList<>();
    private static final Gson _gson = new Gson();

    private static void fill(String[] regexFiles, List<RegexEntity> regexEntityList) {
        Type tArrayListRegexEntity = new TypeToken<ArrayList<RegexEntity>>() {}.getType();

        Stream.of(regexFiles)
            .<List<RegexEntity>>map(regex_file -> _gson.fromJson(Utils.readResourceFile(regex_file), tArrayListRegexEntity))
            .flatMap(Collection::stream)
                //TODO replace with JsonDeserializer
            .map(element -> new RegexEntity(element.getDescription(), element.getRegex(), element.isActive(), element.getSectionsToMatch()))
            .forEach(regexEntityList::add);
    }

    public static List<RegexEntity> getGeneralRegexes() {
        fill(new String[]{"regex_general.json", "regex_token.json", "regex_url.json"}, general_regexes);
        return general_regexes;
    }

    public static List<RegexEntity> getExtensionRegexes() {
        fill(new String[]{"extension_general.json"}, extensions_regexes);
        return extensions_regexes;
    }
}
