package io.github.nithin999989.botguard.core;

import java.time.Duration;
import java.util.Objects;
import java.util.function.Function;

/**
 * One sliding-window rate rule: at most {@code maxRequests} per {@code window}
 * per key, where the key is derived from the request (e.g. client IP).
 */
public final class RateRule {
    private final Function<RequestSnapshot, String> keyExtractor;
    private final long maxRequests;
    private final Duration window;
    private final Verdict verdictOnBreach;

    public RateRule(Function<RequestSnapshot, String> keyExtractor,
                    long maxRequests, Duration window, Verdict verdictOnBreach) {
        if (maxRequests < 1) throw new IllegalArgumentException("maxRequests must be >= 1");
        this.keyExtractor = Objects.requireNonNull(keyExtractor, "keyExtractor");
        this.maxRequests = maxRequests;
        this.window = Objects.requireNonNull(window, "window");
        this.verdictOnBreach = Objects.requireNonNull(verdictOnBreach, "verdictOnBreach");
    }

    public String keyOf(RequestSnapshot request) { return keyExtractor.apply(request); }
    public long maxRequests() { return maxRequests; }
    public Duration window() { return window; }
    public Verdict verdictOnBreach() { return verdictOnBreach; }

    /** Common key extractor: the client IP. */
    public static RateRule perClientIp(long maxRequests, Duration window) {
        return new RateRule(RequestSnapshot::clientIp, maxRequests, window, Verdict.BLOCK);
    }
}
