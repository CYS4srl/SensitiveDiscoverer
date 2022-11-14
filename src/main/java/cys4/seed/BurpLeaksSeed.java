/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.seed;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cys4.controller.Utils;
import cys4.model.ExtensionEntity;
import cys4.model.RegexEntity;

import java.io.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.*;
import java.util.stream.Collectors;


public class BurpLeaksSeed {

    private static final List<RegexEntity> regexes = new ArrayList<RegexEntity>();
    private static final List<ExtensionEntity> extensions = new ArrayList<>();
    private static Gson _gson;

    private static void fill() {

        if(null == _gson) _gson= new Gson();

        Type tArrayListRegexEntity = new TypeToken<ArrayList<RegexEntity>>() {}.getType();
        List<RegexEntity> lDeserializedJson = _gson.fromJson(Utils.readResourceFile("regex.json"), tArrayListRegexEntity);

        for (RegexEntity element: lDeserializedJson)
            regexes.add(new RegexEntity(element.getDescription(), element.getRegex()));
    }

    private static void fill_ext() {

        if(null == _gson) _gson= new Gson();

        Type tArrayListExtensionEntity = new TypeToken<ArrayList<ExtensionEntity>>() {}.getType();
        List<ExtensionEntity> lDeserializedJson = _gson.fromJson(Utils.readResourceFile("extension.json"), tArrayListExtensionEntity);

        for (ExtensionEntity element:lDeserializedJson)
            extensions.add(new ExtensionEntity(element.getDescription(), element.getExtension()));
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