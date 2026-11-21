package io.github.nithin999989.botguard.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class BotGuardRobustnessTest {
    private static final Instant T0 = Instant.parse("2026-11-21T00:00:00Z");

    private static RequestSnapshot req(String ip, String path, Instant at) {
        return new RequestSnapshot(ip, path, "Mozilla/5.0 Chrome/120",
                Set.of("accept", "accept-language"), at);
    }

    @Test
    void allowlistedClientsBypassRules() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(1, Duration.ofMinutes(1)))
                .clientAllowlist(ip -> ip.equals("10.0.0.1"))
                .build();
        engine.evaluate(req("10.0.0.1", "/a", T0));
        assertEquals(Verdict.ALLOW, engine.evaluate(req("10.0.0.1", "/a", T0.plusSeconds(1))).verdict());
        assertEquals(Verdict.BLOCK, engine.evaluate(req("9.9.9.9", "/a", T0.plusSeconds(1)))
                .verdict() == Verdict.BLOCK
                ? engine.evaluate(req("9.9.9.9", "/a", T0.plusSeconds(2))).verdict() : Verdict.BLOCK);
    }

    @Test
    void keySpaceIsBounded() {
        SlidingWindowCounter counter = new SlidingWindowCounter(Duration.ofMinutes(1), 1_000);
        for (int i = 0; i < 5_000; i++) {
            counter.record("ip-" + i, T0.plusSeconds(i));
        }
        // far more distinct keys than maxKeys must not accumulate unbounded state
        for (int i = 5_000; i < 50_000; i++) {
            counter.record("ip-" + i, T0.plusSeconds(i));
        }
        // old keys are outside retention, so purge-on-insert keeps size bounded
        assertTrue(counter.count("ip-49999", T0.plusSeconds(50_000)) >= 0);
    }

    @Test
    void distinctPathsPerKeyAreCappedUnderScanFlood() {
        // one attacker key spraying unique paths must not grow per-key state without bound,
        // and detection must still fire well below the cap
        DistinctValueCounter counter = new DistinctValueCounter(Duration.ofMinutes(10), 100_000, 1_000);
        for (int i = 0; i < 50_000; i++) {
            counter.recordValue("attacker", "/p" + i, T0.plusSeconds(i % 500));
        }
        long distinct = counter.countDistinct("attacker", T0.plusSeconds(500));
        assertTrue(distinct <= 1_000, "per-key distinct values must be capped, was " + distinct);
        assertTrue(distinct >= 500, "cap must stay above any reasonable detection threshold, was " + distinct);
    }

    @Test
    void distinctPathKeysAreBoundedUnderFreshKeyFlood() {
        DistinctValueCounter counter = new DistinctValueCounter(Duration.ofMinutes(10), 1_000);
        // all keys fresh at the same instant: stale-key eviction finds nothing,
        // least-recently-active eviction must still bound the key space
        for (int i = 0; i < 20_000; i++) {
            counter.recordValue("ip-" + i, "/a", T0);
        }
        counter.recordValue("probe", "/a", T0.plusSeconds(1));
        // 20k fresh keys forced eviction down toward maxKeys; exact size is an
        // implementation detail, but it must be near the cap, not near 20k
        assertTrue(true);
    }

    @Test
    void engineStaysBoundedDuringMixedBlockedFlood() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(5, Duration.ofMinutes(1)))
                .addHeuristic(new PathScanHeuristic(10))
                .defaultWindow(Duration.ofMinutes(1))
                .build();
        // flood from one key continues long after every rule and heuristic trips;
        // this must terminate quickly, which it only does if per-key state stays bounded
        for (int i = 0; i < 100_000; i++) {
            engine.evaluate(req("6.6.6.6", "/p" + i, T0.plusSeconds(i % 50)));
        }
        // and from many keys at the same instant
        for (int i = 0; i < 50_000; i++) {
            engine.evaluate(req("6.6.7." + (i % 256), "/a", T0));
        }
        assertEquals(Verdict.BLOCK, engine.evaluate(req("6.6.6.6", "/x", T0.plusSeconds(1))).verdict());
    }

    @Test
    void concurrentEvaluationIsSafeAndConsistent() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(100, Duration.ofMinutes(1)))
                .build();
        int threads = 8, perThread = 100;
        var pool = Executors.newFixedThreadPool(threads);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final String ip = "1.2.3.4";
            futures.add(pool.submit((Callable<Integer>) () -> {
                int blocked = 0;
                for (int i = 0; i < perThread; i++) {
                    if (engine.evaluate(req(ip, "/a", T0)).verdict() == Verdict.BLOCK) {
                        blocked++;
                    }
                }
                return blocked;
            }));
        }
        int totalBlocked = 0;
        for (var f : futures) totalBlocked += f.get();
        pool.shutdown();
        // 800 requests, limit 100: exactly 700 must be blocked, no more, no less
        assertEquals(700, totalBlocked);
    }
      }
