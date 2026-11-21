package io.github.nithin999989.botguard.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BotGuardEngineTest {
    private static final Instant T0 = Instant.parse("2026-11-21T00:00:00Z");

    private static RequestSnapshot req(String ip, String path, String ua, Instant at) {
        return new RequestSnapshot(ip, path, ua, Set.of("accept", "accept-language"), at);
    }

    @Test
    void allowsNormalTraffic() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(5, Duration.ofMinutes(1)))
                .addHeuristic(new UserAgentHeuristic())
                .build();
        var d = engine.evaluate(req("1.2.3.4", "/home",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", T0));
        assertEquals(Verdict.ALLOW, d.verdict());
    }

    @Test
    void blocksAfterRateLimitBreached() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(3, Duration.ofMinutes(1)))
                .build();
        for (int i = 0; i < 3; i++) {
            engine.evaluate(req("1.2.3.4", "/a", "curl/8.0", T0.plusSeconds(i)));
        }
        var d = engine.evaluate(req("1.2.3.4", "/a", "curl/8.0", T0.plusSeconds(3)));
        assertEquals(Verdict.BLOCK, d.verdict());
    }

    @Test
    void rateLimitResetsAfterWindow() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(2, Duration.ofSeconds(10)))
                .build();
        engine.evaluate(req("1.2.3.4", "/a", "x", T0));
        engine.evaluate(req("1.2.3.4", "/a", "x", T0.plusSeconds(1)));
        assertEquals(Verdict.BLOCK, engine.evaluate(req("1.2.3.4", "/a", "x", T0.plusSeconds(2))).verdict());
        assertEquals(Verdict.ALLOW, engine.evaluate(req("1.2.3.4", "/a", "x", T0.plusSeconds(11))).verdict());
    }

    @Test
    void challengesAutomationUserAgent() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addHeuristic(new UserAgentHeuristic())
                .build();
        var d = engine.evaluate(req("1.2.3.4", "/api", "python-requests/2.31", T0));
        assertEquals(Verdict.CHALLENGE, d.verdict());
    }

    @Test
    void challengesMissingUserAgent() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addHeuristic(new UserAgentHeuristic())
                .build();
        var d = engine.evaluate(req("1.2.3.4", "/api", "", T0));
        assertEquals(Verdict.CHALLENGE, d.verdict());
    }

    @Test
    void challengesBrowserUaWithoutBrowserHeaders() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addHeuristic(new HeaderConsistencyHeuristic())
                .build();
        var spoofed = new RequestSnapshot("1.2.3.4", "/shop",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit Chrome/120 Safari/537.36",
                Set.of(), T0);
        assertEquals(Verdict.CHALLENGE, engine.evaluate(spoofed).verdict());
        var real = new RequestSnapshot("1.2.3.4", "/shop",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit Chrome/120 Safari/537.36",
                Set.of("accept", "accept-language"), T0);
        assertEquals(Verdict.ALLOW, engine.evaluate(real).verdict());
    }

    @Test
    void blocksEndpointScanning() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addHeuristic(new PathScanHeuristic(3))
                .build();
        for (int i = 0; i < 3; i++) {
            engine.evaluate(req("1.2.3.4", "/p" + i, "x", T0.plusSeconds(i)));
        }
        var d = engine.evaluate(req("1.2.3.4", "/p3", "x", T0.plusSeconds(3)));
        assertEquals(Verdict.BLOCK, d.verdict());
    }

    @Test
    void separateKeysDoNotShareRateLimits() {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(2, Duration.ofMinutes(1)))
                .build();
        engine.evaluate(req("1.1.1.1", "/a", "x", T0));
        engine.evaluate(req("1.1.1.1", "/a", "x", T0.plusSeconds(1)));
        assertEquals(Verdict.BLOCK, engine.evaluate(req("1.1.1.1", "/a", "x", T0.plusSeconds(2))).verdict());
        assertEquals(Verdict.ALLOW, engine.evaluate(req("2.2.2.2", "/a", "x", T0.plusSeconds(2))).verdict());
    }
  }
