package io.github.nithin999989.botguard.core;

/**
 * Decision for one request. Severity increases downward;
 * the engine returns the strictest verdict produced by any rule.
 */
public enum Verdict {
    ALLOW,
    CHALLENGE,
    BLOCK
}
