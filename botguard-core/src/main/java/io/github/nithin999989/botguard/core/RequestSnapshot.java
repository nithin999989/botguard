package io.github.nithin999989.botguard.core;

import java.time.Instant;
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable view of the request attributes BotGuard evaluates.
 * Framework adapters (Servlet, WebFlux) build this from the live request.
 */
public final class RequestSnapshot {
    private final String clientIp;
    private final String path;
    private final String userAgent;
    private final Set<String> headerNames;
    private final Instant timestamp;

    public RequestSnapshot(String clientIp, String path, String userAgent,
                           Set<String> headerNames, Instant timestamp) {
        this.clientIp = Objects.requireNonNull(clientIp, "clientIp");
        this.path = path == null ? "/" : path;
        this.userAgent = userAgent == null ? "" : userAgent;
        Set<String> lower = new java.util.TreeSet<>();
        if (headerNames != null) {
            for (String h : headerNames) lower.add(h.toLowerCase(Locale.ROOT));
        }
        this.headerNames = Collections.unmodifiableSet(lower);
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
    }

    public String clientIp() { return clientIp; }
    public String path() { return path; }
    public String userAgent() { return userAgent; }
    public boolean hasHeader(String name) { return headerNames.contains(name.toLowerCase(Locale.ROOT)); }
    public Instant timestamp() { return timestamp; }
}
