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

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

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

    /**
     * Converts a list of serialized sections to an EnumSet of sections
     *
     * @param sections List of the serialized sections
     * @return An EnumSet with all the sections in the given list
     */
    public static EnumSet<ProxyItemSection> deserializeSections(List<String> sections) {
        if (Objects.isNull(sections))
            return ProxyItemSection.getDefault();

        return sections
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

    /**
     * Convert an EnumSet of sections into a list of serialized sections
     * @param sections EnumSet of sections
     * @return A list of the sections in the EnumSet as serialized strings
     */
    public static List<String> serializeSections(EnumSet<ProxyItemSection> sections) {
        return sections
                .stream()
                .flatMap(section -> switch (section) {
                    case REQ_URL -> Stream.of("req_url");
                    case REQ_BODY -> Stream.of("req_headers");
                    case REQ_HEADERS -> Stream.of("req_body");
                    case RES_BODY -> Stream.of("res_headers");
                    case RES_HEADERS -> Stream.of("res_body");
                    default -> null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.<String>toList());
    }

    @Override
    public String toString() {
        return switch (this) {
            case REQ_URL -> getLocaleString("regex-section-reqURL");
            case REQ_BODY -> getLocaleString("regex-section-reqBody");
            case REQ_HEADERS -> getLocaleString("regex-section-reqHeaders");
            case RES_BODY -> getLocaleString("regex-section-resBody");
            case RES_HEADERS -> getLocaleString("regex-section-resHeaders");
            default -> this.name();
        };
    }
}
