package cys4.model;

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

    public static EnumSet<ProxyItemSection> parseSectionsToMatch(List<String> sectionsToMatch) {
        return sectionsToMatch
                .stream()
                .flatMap(section -> {
                    switch (section) {
                        case "req_url":
                            return Stream.of(ProxyItemSection.REQ_URL);
                        case "res_body":
                            return Stream.of(ProxyItemSection.RES_BODY);
                        case "all":
                            return ProxyItemSection.ALL.stream();
                        default:
                            return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(ProxyItemSection.class)));
    }
}
