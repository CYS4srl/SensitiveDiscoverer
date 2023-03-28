/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Enum to identify all the various section that a regex can match in an HttpProxyItem object.
 */
public enum ProxyItemSection {
    REQ_URL,
    REQ_HEADERS,
    REQ_BODY,
    RES_HEADERS,
    RES_BODY;

    public static final EnumSet<ProxyItemSection> REQ = EnumSet.of(
            ProxyItemSection.REQ_URL, ProxyItemSection.REQ_HEADERS, ProxyItemSection.REQ_BODY);
    public static final EnumSet<ProxyItemSection> RES = EnumSet.of(
            ProxyItemSection.RES_HEADERS, ProxyItemSection.RES_BODY);
    public static final EnumSet<ProxyItemSection> ALL = EnumSet.allOf(
            ProxyItemSection.class);

    public static EnumSet<ProxyItemSection> getDefault() {
        return ProxyItemSection.RES;
    }

    public static EnumSet<ProxyItemSection> parseSectionsToMatch(List<String> sectionsToMatch) {
        if (Objects.isNull(sectionsToMatch))
            return ProxyItemSection.getDefault();

        return sectionsToMatch
            .stream()
            .flatMap(section -> switch (section) {
                case "req_url" -> Stream.of(ProxyItemSection.REQ_URL);
                case "req_headers" -> Stream.of(ProxyItemSection.REQ_HEADERS);
                case "req_body" -> Stream.of(ProxyItemSection.REQ_BODY);
                case "res_headers" -> Stream.of(ProxyItemSection.RES_HEADERS);
                case "res_body" -> Stream.of(ProxyItemSection.RES_BODY);
                case "req" -> ProxyItemSection.REQ.stream();
                case "res" -> ProxyItemSection.RES.stream();
                case "all" -> ProxyItemSection.ALL.stream();
                default -> null;
            })
            .filter(Objects::nonNull)
            .collect(Collectors.toCollection(() -> EnumSet.noneOf(ProxyItemSection.class)));
    }

    @Override
    public String toString() {
        return switch (this) {
            case REQ_URL -> "RequestURL";
            case REQ_BODY -> "RequestBody";
            case REQ_HEADERS -> "RequestHeaders";
            case RES_BODY -> "ResponseBody";
            case RES_HEADERS -> "ResponseHeaders";
            default -> this.name();
        };
    }
}
