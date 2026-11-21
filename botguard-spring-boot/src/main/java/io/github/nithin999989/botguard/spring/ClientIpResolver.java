package io.github.nithin999989.botguard.spring;

import javax.servlet.http.HttpServletRequest;

/**
 * Resolves the client identity for rate rules and heuristics.
 *
 * The default ({@link #direct()}) uses the connection's remote address and
 * ignores forwarding headers. Only use a forwarding-header resolver when the
 * service sits behind a proxy you control - X-Forwarded-For is trivially
 * spoofable by direct clients.
 */
@FunctionalInterface
public interface ClientIpResolver {
    String resolve(HttpServletRequest request);

    /** Direct connection address; safe default. */
    static ClientIpResolver direct() {
        return HttpServletRequest::getRemoteAddr;
    }

    /**
     * Leftmost X-Forwarded-For entry. Use only behind a trusted proxy that
     * overwrites this header; otherwise clients can spoof their identity.
     */
    static ClientIpResolver xForwardedFor() {
        return request -> {
            String header = request.getHeader("X-Forwarded-For");
            if (header == null || header.isBlank()) {
                return request.getRemoteAddr();
            }
            int comma = header.indexOf(',');
            return (comma < 0 ? header : header.substring(0, comma)).trim();
        };
    }
}
