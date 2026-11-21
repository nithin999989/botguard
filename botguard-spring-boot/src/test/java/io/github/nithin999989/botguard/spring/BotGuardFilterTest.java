package io.github.nithin999989.botguard.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.nithin999989.botguard.core.BotGuardEngine;
import io.github.nithin999989.botguard.core.RateRule;
import io.github.nithin999989.botguard.core.UserAgentHeuristic;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

/**
 * Exercises the servlet filter itself against a minimal stubbed servlet API:
 * verdict mapping (403/429/pass-through) and client-IP resolution.
 */
class BotGuardFilterTest {

    private static HttpServletRequest request(String remoteAddr, String uri, String userAgent,
                                              Map<String, String> headers) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "getRemoteAddr": return remoteAddr;
                case "getRequestURI": return uri;
                case "getHeader": return headers.getOrDefault((String) args[0],
                        "User-Agent".equals(args[0]) ? userAgent : null);
                case "getHeaderNames": return Collections.enumeration(headers.keySet());
                case "getMethod": return "GET";
                default:
                    Class<?> rt = method.getReturnType();
                    if (rt == int.class) return 0;
                    if (rt == boolean.class) return false;
                    if (rt == Enumeration.class) return Collections.emptyEnumeration();
                    return null;
            }
        };
        return (HttpServletRequest) Proxy.newProxyInstance(
                BotGuardFilterTest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class}, handler);
    }

    private static final class StubResponse {
        final AtomicInteger status = new AtomicInteger(200);
        final AtomicBoolean chainCalled = new AtomicBoolean(false);

        HttpServletResponse proxy() {
            InvocationHandler handler = (proxy, method, args) -> {
                switch (method.getName()) {
                    case "sendError":
                        status.set((Integer) args[0]);
                        return null;
                    case "setStatus":
                        status.set((Integer) args[0]);
                        return null;
                    default:
                        Class<?> rt = method.getReturnType();
                        if (rt == int.class) return 0;
                        if (rt == boolean.class) return false;
                        return null;
                }
            };
            return (HttpServletResponse) Proxy.newProxyInstance(
                    BotGuardFilterTest.class.getClassLoader(), new Class<?>[] {HttpServletResponse.class}, handler);
        }

        FilterChain chain() {
            return (req, res) -> chainCalled.set(true);
        }
    }

    private static Map<String, String> noHeaders() {
        return new HashMap<>();
    }

    @Test
    void allowedRequestPassesThroughToChain() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder() // permissive rule that never trips
                .addRule(RateRule.perClientIp(1_000_000, Duration.ofMinutes(1)))
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine);
        StubResponse res = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/index", "Mozilla/5.0", noHeaders()), res.proxy(), res.chain());
        assertTrue(res.chainCalled.get());
        assertEquals(200, res.status.get());
    }

    @Test
    void blockedRequestGets403AndStops() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(1, Duration.ofMinutes(1)))
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine);
        StubResponse first = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", noHeaders()), first.proxy(), first.chain());
        assertTrue(first.chainCalled.get());

        StubResponse second = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", noHeaders()), second.proxy(), second.chain());
        assertFalse(second.chainCalled.get());
        assertEquals(403, second.status.get());
    }

    @Test
    void challengedRequestGets429ByDefault() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addHeuristic(new UserAgentHeuristic())
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine);
        StubResponse res = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "curl/8.0.1", noHeaders()), res.proxy(), res.chain());
        assertFalse(res.chainCalled.get());
        assertEquals(429, res.status.get());
    }

    @Test
    void allowlistedClientBypassesRules() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(1, Duration.ofMinutes(1)))
                .clientAllowlist(ip -> ip.equals("10.0.0.1"))
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine);
        StubResponse first = new StubResponse();
        StubResponse second = new StubResponse();
        filter.doFilter(request("10.0.0.1", "/a", "Mozilla/5.0", noHeaders()), first.proxy(), first.chain());
        filter.doFilter(request("10.0.0.1", "/a", "Mozilla/5.0", noHeaders()), second.proxy(), second.chain());
        assertTrue(second.chainCalled.get());
    }

    @Test
    void directResolverIgnoresSpoofedForwardedFor() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(1, Duration.ofMinutes(1)))
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine, ClientIpResolver.direct());
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Forwarded-For", "9.9.9.9"); // spoof attempt: different identity per request
        StubResponse first = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", headers), first.proxy(), first.chain());
        headers.put("X-Forwarded-For", "8.8.8.8");
        StubResponse second = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", headers), second.proxy(), second.chain());
        // direct() keys on the connection address, so the second request from the
        // same connection must be blocked despite the spoofed header
        assertFalse(second.chainCalled.get());
        assertEquals(403, second.status.get());
    }

    @Test
    void xForwardedForResolverUsesLeftmostEntry() throws Exception {
        BotGuardEngine engine = BotGuardEngine.builder()
                .addRule(RateRule.perClientIp(1, Duration.ofMinutes(1)))
                .build();
        BotGuardFilter filter = new BotGuardFilter(engine, ClientIpResolver.xForwardedFor());
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Forwarded-For", "9.9.9.9, 10.0.0.5");
        StubResponse first = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", headers), first.proxy(), first.chain());
        assertTrue(first.chainCalled.get());
        headers.put("X-Forwarded-For", "8.8.8.8");
        StubResponse second = new StubResponse();
        filter.doFilter(request("1.2.3.4", "/a", "Mozilla/5.0", headers), second.proxy(), second.chain());
        // behind a trusted proxy, a different leftmost entry is a different client
        assertTrue(second.chainCalled.get());
    }
}
