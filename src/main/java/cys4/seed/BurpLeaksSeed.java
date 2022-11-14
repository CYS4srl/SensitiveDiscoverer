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
import java.util.List;

public class BurpLeaksSeed {

    private static final List<RegexEntity> regexes = new ArrayList<RegexEntity>();
    private static final List<ExtensionEntity> extensions = new ArrayList<>();
    private static Gson _gson = new Gson();

    private static void fill() {
        Type tArrayListRegexEntity = new TypeToken<ArrayList<RegexEntity>>() {}.getType();
        List<RegexEntity> lDeserializedJson = _gson.fromJson(Utils.readResourceFile("regex.json"), tArrayListRegexEntity);

        for (RegexEntity element : lDeserializedJson) {
            regexes.add(new RegexEntity(element.getDescription(), element.getRegex(), element.isActive()));
        }
    }

    private static void fill_ext() {
        Type tArrayListExtensionEntity = new TypeToken<ArrayList<ExtensionEntity>>() {}.getType();
        List<ExtensionEntity> lDeserializedJson = _gson.fromJson(Utils.readResourceFile("extension.json"), tArrayListExtensionEntity);

        for (ExtensionEntity element : lDeserializedJson) {
            extensions.add(new ExtensionEntity(element.getDescription(), element.getExtension(), element.isActive()));
        }
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
