package io.github.nithin999989.botguard.core;

import java.util.Locale;
import java.util.Optional;

/**
 * Catches a common bot tell: a browser User-Agent without the headers
 * real browsers always send (Accept, Accept-Language). A request claiming
 * to be Chrome that sends neither is very likely scripted.
 */
public final class HeaderConsistencyHeuristic implements Heuristic {
    @Override
    public Optional<Signal> evaluate(RequestSnapshot request, ActivityState state) {
        String ua = request.userAgent().toLowerCase(Locale.ROOT);
        boolean claimsBrowser = ua.contains("mozilla/") && (ua.contains("chrome") || ua.contains("safari") || ua.contains("firefox"));
        if (!claimsBrowser) {
            return Optional.empty();
        }
        boolean missingAccept = !request.hasHeader("accept");
        boolean missingAcceptLanguage = !request.hasHeader("accept-language");
        if (missingAccept && missingAcceptLanguage) {
            return Optional.of(new Signal(Verdict.CHALLENGE,
                    "browser user-agent without accept/accept-language headers"));
        }
        return Optional.empty();
    }
}
