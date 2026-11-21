package io.github.nithin999989.botguard.core;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts how many distinct values (e.g. request paths) a key produced
 * inside a trailing time window. Used for scan detection, where a single
 * client touching many different endpoints quickly is suspicious.
 */
public final class DistinctValueCounter {
    private static final int DEFAULT_MAX_KEYS = 100_000;
    private static final int DEFAULT_MAX_VALUES_PER_KEY = 10_000;

    private final Map<String, Map<String, Long>> seenAtByKeyAndValue = new ConcurrentHashMap<>();
    private final long windowSeconds;
    private final int maxKeys;
    private final int maxValuesPerKey;

    public DistinctValueCounter(Duration window) {
        this(window, DEFAULT_MAX_KEYS, DEFAULT_MAX_VALUES_PER_KEY);
    }

    public DistinctValueCounter(Duration window, int maxKeys) {
        this(window, maxKeys, DEFAULT_MAX_VALUES_PER_KEY);
    }

    public DistinctValueCounter(Duration window, int maxKeys, int maxValuesPerKey) {
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (maxKeys < 1) {
            throw new IllegalArgumentException("maxKeys must be >= 1");
        }
        if (maxValuesPerKey < 1) {
            throw new IllegalArgumentException("maxValuesPerKey must be >= 1");
        }
        this.windowSeconds = window.getSeconds();
        this.maxKeys = maxKeys;
        this.maxValuesPerKey = maxValuesPerKey;
    }

    /**
     * Records that {@code key} touched {@code value} at {@code at}.
     * Values are attacker-influenceable (request paths), so the per-key set is
     * capped: once a key reaches maxValuesPerKey distinct values, new values
     * are no longer recorded. Detection thresholds below the cap still see the
     * true count, and a key already over any reasonable threshold keeps its
     * verdict; the cap only stops unbounded memory growth during a scan flood.
     */
    public void recordValue(String key, String value, Instant at) {
        if (seenAtByKeyAndValue.size() > maxKeys && !seenAtByKeyAndValue.containsKey(key)) {
            evictStaleKeys(at);
            if (seenAtByKeyAndValue.size() > maxKeys) {
                evictLeastRecentlyActiveKey();
            }
        }
        Map<String, Long> seenAt = seenAtByKeyAndValue.computeIfAbsent(key, k -> new HashMap<>());
        synchronized (seenAt) {
            Long existing = seenAt.get(value);
            if (existing != null) {
                seenAt.put(value, at.getEpochSecond());
            } else if (seenAt.size() < maxValuesPerKey) {
                seenAt.put(value, at.getEpochSecond());
            }
            evict(seenAt, at);
        }
    }

    public long countDistinct(String key, Instant now) {
        Map<String, Long> seenAt = seenAtByKeyAndValue.get(key);
        if (seenAt == null) return 0;
        long cutoff = now.getEpochSecond() - windowSeconds;
        synchronized (seenAt) {
            return seenAt.values().stream().filter(ts -> ts > cutoff).count();
        }
    }

    private void evict(Map<String, Long> seenAt, Instant now) {
        long cutoff = now.getEpochSecond() - (windowSeconds * 2 + 60);
        seenAt.values().removeIf(ts -> ts < cutoff);
    }

    private void evictStaleKeys(Instant now) {
        long cutoff = now.getEpochSecond() - (windowSeconds * 2 + 60);
        seenAtByKeyAndValue.entrySet().removeIf(e -> {
            Map<String, Long> m = e.getValue();
            synchronized (m) {
                evict(m, now);
                return m.isEmpty();
            }
        });
    }

    private void evictLeastRecentlyActiveKey() {
        // Approximate eviction: drop the keys whose newest value timestamp is oldest.
        seenAtByKeyAndValue.entrySet().stream()
                .sorted(java.util.Comparator.comparingLong(e -> {
                    Map<String, Long> m = e.getValue();
                    synchronized (m) {
                        return m.values().stream().mapToLong(Long::longValue).max().orElse(Long.MIN_VALUE);
                    }
                }))
                .limit(Math.max(1, seenAtByKeyAndValue.size() - maxKeys))
                .forEach(e -> seenAtByKeyAndValue.remove(e.getKey()));
    }
}
