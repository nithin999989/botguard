package io.github.nithin999989.botguard.core;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Flags requests whose User-Agent is missing or matches known
 * automation/tooling signatures (scripting runtimes, HTTP libraries,
 * headless browsers, well-known scrapers).
 *
 * This is a weak signal on its own - plenty of legitimate API clients
 * identify as curl - so the default verdict is CHALLENGE, not BLOCK.
 */
public final class UserAgentHeuristic implements Heuristic {
    private static final List<Pattern> TOOLING = List.of(
            Pattern.compile("curl/\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wget/\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("python-requests|aiohttp|httpx", Pattern.CASE_INSENSITIVE),
            Pattern.compile("headlesschrome|phantomjs|puppeteer|playwright", Pattern.CASE_INSENSITIVE),
            Pattern.compile("scrapy|java/\\d|okhttp|go-http-client", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public Optional<Signal> evaluate(RequestSnapshot request, ActivityState state) {
        String ua = request.userAgent();
        if (ua.isBlank()) {
            return Optional.of(new Signal(Verdict.CHALLENGE, "missing user-agent"));
        }
        for (Pattern p : TOOLING) {
            if (p.matcher(ua).find()) {
                return Optional.of(new Signal(Verdict.CHALLENGE,
                        "automation user-agent: " + ua.toLowerCase(Locale.ROOT)));
            }
        }
        return Optional.empty();
    }
}
