package io.github.nithin999989.botguard.core;

import java.util.Optional;

/**
 * A stateless signal extractor. Heuristics never decide on their own;
 * they contribute a {@link Signal} that the engine weighs with others.
 */
public interface Heuristic {
    /**
     * @param request the request under evaluation
     * @param state   per-key recent activity view (rate/velocity data)
     * @return a signal when the heuristic has something to say, else empty
     */
    Optional<Signal> evaluate(RequestSnapshot request, ActivityState state);

    /** One heuristic's opinion about a request. */
    final class Signal {
        private final Verdict verdict;
        private final String reason;

        public Signal(Verdict verdict, String reason) {
            this.verdict = verdict;
            this.reason = reason;
        }

        public Verdict verdict() { return verdict; }
        public String reason() { return reason; }
    }

    /** Recent-activity view heuristics can query without owning storage. */
    interface ActivityState {
        long requestsInWindow(String key);
        long distinctPathsInWindow(String key);
    }
}
