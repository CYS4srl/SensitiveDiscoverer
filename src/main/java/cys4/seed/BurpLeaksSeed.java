/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.seed;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cys4.controller.Utils;
import cys4.model.ExtensionEntity;
import cys4.model.RegexEntity;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

public class BurpLeaksSeed {

    private static final List<RegexEntity> regexes = new ArrayList<>();
    private static final List<ExtensionEntity> extensions = new ArrayList<>();
    private static final Gson _gson = new Gson();

    private static void fill() {
        Type tArrayListRegexEntity = new TypeToken<ArrayList<RegexEntity>>() {}.getType();

        Stream.of("regex_general.json", "regex_token.json", "regex_url.json")
            .<List<RegexEntity>>map(regex_file -> _gson.fromJson(Utils.readResourceFile(regex_file), tArrayListRegexEntity))
            .flatMap(Collection::stream)
            .map(element -> new RegexEntity(element.getDescription(), element.getRegex(), element.isActive()))
            .forEach(regexes::add);
    }

    private static void fill_ext() {
        Type tArrayListExtensionEntity = new TypeToken<ArrayList<ExtensionEntity>>() {}.getType();

        Stream.of("extension_general.json")
            .<List<ExtensionEntity>>map(regex_file -> _gson.fromJson(Utils.readResourceFile(regex_file), tArrayListExtensionEntity))
            .flatMap(Collection::stream)
            .map(element -> new ExtensionEntity(element.getDescription(), element.getRegex(), element.isActive()))
            .forEach(extensions::add);
    }

    public static List<RegexEntity> getRegex() {
        fill();
        return regexes;
    }

    public static List<ExtensionEntity> getExtensions() {
        fill_ext();
        return extensions;
    }
}
