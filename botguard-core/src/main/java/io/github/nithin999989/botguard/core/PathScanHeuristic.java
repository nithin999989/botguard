package io.github.nithin999989.botguard.core;

import java.util.Optional;

/**
 * Detects endpoint scanning: one client touching many distinct paths
 * inside a short window. Normal users revisit a handful of routes;
 * scanners fan out. Configurable threshold per window.
 */
public final class PathScanHeuristic implements Heuristic {
    private final long maxDistinctPathsPerWindow;

    public PathScanHeuristic(long maxDistinctPathsPerWindow) {
        if (maxDistinctPathsPerWindow < 1) {
            throw new IllegalArgumentException("threshold must be >= 1");
        }
        this.maxDistinctPathsPerWindow = maxDistinctPathsPerWindow;
    }

    @Override
    public Optional<Signal> evaluate(RequestSnapshot request, ActivityState state) {
        long distinct = state.distinctPathsInWindow(request.clientIp());
        if (distinct > maxDistinctPathsPerWindow) {
            return Optional.of(new Signal(Verdict.BLOCK,
                    "endpoint scanning: " + distinct + " distinct paths in window (limit "
                            + maxDistinctPathsPerWindow + ")"));
        }
        return Optional.empty();
    }
}
