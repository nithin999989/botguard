package io.github.nithin999989.botguard.core;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory sliding-window event counter, one logical counter per key.
 * Buckets events at 1-second granularity and keeps only the tail window,
 * so memory stays bounded by windowSeconds per key rather than by event count.
 *
 * Intended for a single application node; pair with a shared store
 * (e.g. Redis) when running many nodes behind a load balancer.
 */
public final class SlidingWindowCounter {
    private static final class Bucket {
        long epochSecond;
        int count;
    }

    private static final int DEFAULT_MAX_KEYS = 100_000;

    private final Map<String, Deque<Bucket>> bucketsByKey = new ConcurrentHashMap<>();
    private final long windowSeconds;
    private final long retentionSeconds;
    private final int maxKeys;

    public SlidingWindowCounter(Duration window) {
        this(window, DEFAULT_MAX_KEYS);
    }

    public SlidingWindowCounter(Duration window, int maxKeys) {
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (maxKeys < 1) {
            throw new IllegalArgumentException("maxKeys must be >= 1");
        }
        this.windowSeconds = window.getSeconds();
        // Keep a little history beyond the window so queries near the
        // boundary stay correct, without unbounded growth.
        this.retentionSeconds = windowSeconds * 2 + 60;
        this.maxKeys = maxKeys;
    }

    /**
     * Records one event for {@code key} at {@code at}.
     * Keys are attacker-influenceable (e.g. client IPs), so the key space is
     * bounded: when the map exceeds maxKeys, keys with no events inside the
     * retention window are evicted first, and if still over capacity the
     * least-recently-active keys are dropped.
     */
    public void record(String key, Instant at) {
        if (bucketsByKey.size() > maxKeys && !bucketsByKey.containsKey(key)) {
            purgeStaleKeys(at);
            if (bucketsByKey.size() > maxKeys) {
                evictLeastRecentlyActive();
            }
        }
        Deque<Bucket> buckets = bucketsByKey.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (buckets) {
            if (!buckets.isEmpty() && buckets.peekLast().epochSecond == at.getEpochSecond()) {
                buckets.peekLast().count++;
            } else {
                Bucket b = new Bucket();
                b.epochSecond = at.getEpochSecond();
                b.count = 1;
                buckets.addLast(b);
            }
            evict(buckets, at);
        }
    }

    /** Total events for {@code key} inside the trailing window ending at {@code now}. */
    public long count(String key, Instant now) {
        Deque<Bucket> buckets = bucketsByKey.get(key);
        if (buckets == null) return 0;
        long cutoff = now.getEpochSecond() - windowSeconds;
        synchronized (buckets) {
            long total = 0;
            for (Bucket b : buckets) {
                if (b.epochSecond > cutoff) total += b.count;
            }
            return total;
        }
    }

    private void evict(Deque<Bucket> buckets, Instant now) {
        long cutoff = now.getEpochSecond() - retentionSeconds;
        while (!buckets.isEmpty() && buckets.peekFirst().epochSecond < cutoff) {
            buckets.pollFirst();
        }
    }

    private void evictLeastRecentlyActive() {
        // Approximate eviction: drop keys whose newest bucket is oldest.
        bucketsByKey.entrySet().stream()
                .sorted(java.util.Comparator.comparingLong(e -> {
                    Deque<Bucket> b = e.getValue();
                    synchronized (b) {
                        return b.isEmpty() ? Long.MIN_VALUE : b.peekLast().epochSecond;
                    }
                }))
                .limit(Math.max(1, bucketsByKey.size() - maxKeys))
                .forEach(e -> bucketsByKey.remove(e.getKey()));
    }

    /** Removes all state for keys not seen recently; call periodically under load. */
    public void purgeStaleKeys(Instant now) {
        bucketsByKey.entrySet().removeIf(e -> {
            Deque<Bucket> buckets = e.getValue();
            synchronized (buckets) {
                evict(buckets, now);
                return buckets.isEmpty();
            }
        });
    }
}
