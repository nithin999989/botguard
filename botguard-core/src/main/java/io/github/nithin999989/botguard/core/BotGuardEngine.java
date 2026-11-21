package io.github.nithin999989.botguard.core;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Evaluates requests against rate rules and heuristics and returns the
 * strictest resulting verdict. Thread-safe: storage is concurrent and
 * heuristics are stateless.
 */
public final class BotGuardEngine {
    private final List<RateRule> rules;
    private final List<Heuristic> heuristics;
    private final java.util.function.Predicate<String> clientAllowlist;
    private final Map<RateRule, SlidingWindowCounter> countersByRule;
    private final SlidingWindowCounter activityCounter;
    private final DistinctValueCounter pathCounter;

    private BotGuardEngine(Builder b) {
        this.rules = List.copyOf(b.rules);
        this.heuristics = List.copyOf(b.heuristics);
        Map<RateRule, SlidingWindowCounter> counters = new java.util.IdentityHashMap<>();
        for (RateRule rule : rules) {
            counters.put(rule, new SlidingWindowCounter(rule.window()));
        }
        this.countersByRule = counters;
        this.activityCounter = new SlidingWindowCounter(b.defaultWindow);
        this.pathCounter = new DistinctValueCounter(b.defaultWindow);
        this.clientAllowlist = b.clientAllowlist;
    }

    /** Evaluates one request, recording its activity for future windows. */
    public Decision evaluate(RequestSnapshot request) {
        Objects.requireNonNull(request, "request");
        Instant now = request.timestamp();

        if (clientAllowlist.test(request.clientIp())) {
            return Decision.allow();
        }

        // Record activity first so the current request counts toward its own window.
        activityCounter.record(request.clientIp(), now);
        pathCounter.recordValue(request.clientIp(), request.path(), now);
        for (RateRule rule : rules) {
            countersByRule.get(rule).record(rule.keyOf(request), now);
        }

        Heuristic.ActivityState state = new Heuristic.ActivityState() {
            @Override public long requestsInWindow(String key) { return activityCounter.count(key, now); }
            @Override public long distinctPathsInWindow(String key) { return pathCounter.countDistinct(key, now); }
        };

        Decision strictest = Decision.allow();
        for (RateRule rule : rules) {
            long count = countersByRule.get(rule).count(rule.keyOf(request), now);
            if (count > rule.maxRequests()) {
                strictest = strictest.strictest(
                        new Decision(rule.verdictOnBreach(),
                                "rate limit breached: " + count + " requests in " + rule.window().getSeconds()
                                        + "s window (limit " + rule.maxRequests() + ")"));
            }
        }
        for (Heuristic h : heuristics) {
            java.util.Optional<Heuristic.Signal> signal = h.evaluate(request, state);
            if (signal.isPresent()) {
                Heuristic.Signal sig = signal.get();
                strictest = strictest.strictest(new Decision(sig.verdict(), sig.reason()));
            }
        }
        return strictest;
    }

    /** Verdict plus the human-readable reason that produced it. */
    public static final class Decision {
        private static final Decision ALLOW = new Decision(Verdict.ALLOW, "no rule or heuristic objected");
        private final Verdict verdict;
        private final String reason;

        public Decision(Verdict verdict, String reason) {
            this.verdict = verdict;
            this.reason = reason;
        }

        public static Decision allow() { return ALLOW; }
        public Verdict verdict() { return verdict; }
        public String reason() { return reason; }

        Decision strictest(Decision other) {
            return other.verdict.ordinal() > this.verdict.ordinal() ? other : this;
        }
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private final List<RateRule> rules = new ArrayList<>();
        private final List<Heuristic> heuristics = new ArrayList<>();
        private Duration defaultWindow = Duration.ofMinutes(1);
        private java.util.function.Predicate<String> clientAllowlist = ip -> false;

        public Builder addRule(RateRule rule) { rules.add(rule); return this; }
        public Builder addHeuristic(Heuristic heuristic) { heuristics.add(heuristic); return this; }

        /** Window used by the engine's built-in activity tracking (default 1 minute). */
        public Builder defaultWindow(Duration window) { this.defaultWindow = window; return this; }

        /**
         * Clients (by resolved IP) that always pass, e.g. your own monitoring
         * or trusted internal services. Heuristics and rate rules are skipped
         * for allowlisted clients. Default: nobody is allowlisted.
         */
        public Builder clientAllowlist(java.util.function.Predicate<String> allowlist) {
            this.clientAllowlist = allowlist;
            return this;
        }

        public BotGuardEngine build() {
            if (rules.isEmpty() && heuristics.isEmpty()) {
                throw new IllegalStateException("configure at least one rule or heuristic");
            }
            return new BotGuardEngine(this);
        }
    }
}
