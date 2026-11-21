package io.github.nithin999989.botguard.spring;

import io.github.nithin999989.botguard.core.BotGuardEngine;
import io.github.nithin999989.botguard.core.RequestSnapshot;
import io.github.nithin999989.botguard.core.Verdict;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Servlet filter adapter. Applies the engine's verdict:
 * BLOCK -> 403, CHALLENGE -> 429 by default (override {@link #onChallenge}),
 * ALLOW -> the request proceeds.
 *
 * All heuristics are opt-in via the engine configuration; the filter itself
 * adds no implicit rules.
 */
public class BotGuardFilter extends javax.servlet.http.HttpFilter {
    private final BotGuardEngine engine;
    private final ClientIpResolver ipResolver;

    public BotGuardFilter(BotGuardEngine engine) {
        this(engine, ClientIpResolver.direct());
    }

    public BotGuardFilter(BotGuardEngine engine, ClientIpResolver ipResolver) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.ipResolver = Objects.requireNonNull(ipResolver, "ipResolver");
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        Set<String> headerNames = new HashSet<>();
        Collections.list(request.getHeaderNames()).forEach(headerNames::add);
        RequestSnapshot snapshot = new RequestSnapshot(
                ipResolver.resolve(request),
                request.getRequestURI(),
                request.getHeader("User-Agent"),
                headerNames,
                Instant.now());

        BotGuardEngine.Decision decision = engine.evaluate(snapshot);
        if (decision.verdict() == Verdict.BLOCK) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, decision.reason());
            return;
        }
        if (decision.verdict() == Verdict.CHALLENGE) {
            onChallenge(request, response, chain, decision);
            return;
        }
        chain.doFilter(request, response);
    }

    /** Default challenge handling: HTTP 429. Override for captcha/throttling. */
    protected void onChallenge(HttpServletRequest request, HttpServletResponse response,
                               FilterChain chain, BotGuardEngine.Decision decision)
            throws IOException, ServletException {
        response.sendError(429, decision.reason());
    }
}
