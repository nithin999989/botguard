# botguard

An experimental Java library for request screening: per-key rate rules plus
opt-in heuristics that flag clients behaving like scanners or scripted
automation. It is a decision engine, not a firewall appliance: you ask it for
a verdict (`ALLOW`, `CHALLENGE`, or `BLOCK`) with a human-readable reason, and
your application decides what to do with it.

**Status: v0.1, experimental.** This is early-stage software built by one
developer. It has a small test suite and has not been validated against
real-world traffic. It is *not* proven bot detection. Determined bots can
evade every heuristic here, and every heuristic can produce false positives.
Treat it as a starting point, measure on your own traffic, and contribute.

## What it does

- **Rate rules** - per-key (e.g. per client IP) sliding-window request limits.
  Keys are pluggable, so you can rate-limit by IP, account id, or API token.
- **User-agent heuristic (opt-in)** - flags missing UAs and known automation
  signatures (curl, python-requests, headless Chrome, ...) as a *challenge*
  signal, not a block, because legitimate API clients exist.
- **Header-consistency heuristic (opt-in)** - flags requests claiming to be a
  browser without the headers real browsers always send.
- **Path-scan heuristic (opt-in)** - blocks clients touching an unusual number
  of distinct paths inside a short window (classic scanner behaviour).

The engine returns the strictest verdict across all rules and heuristics.
Heuristics are only active when you add them; the defaults screen nothing.

## What it does not do

- It cannot identify bots reliably. Heuristics are signals, not proof.
- It does not replace a WAF, authentication, or rate limiting at the edge
  (CDN/load balancer) for large attacks. All state is in-process memory.
- Multi-instance deployments share nothing; each instance counts separately.

## False positives and trusted clients

Every heuristic can be wrong. Mobile apps, embedded clients, corporate
proxies, and monitoring probes can look exactly like bots. That is why:

- Heuristics are opt-in, and most return `CHALLENGE` rather than `BLOCK`.
- You can exempt known clients (your own health checks, partner services)
  with a client allowlist.

```java
BotGuardEngine engine = BotGuardEngine.builder()
        .addRule(RateRule.perClientIp(60, Duration.ofMinutes(1)))
        .addHeuristic(new UserAgentHeuristic())
        .addHeuristic(new HeaderConsistencyHeuristic())
        .addHeuristic(new PathScanHeuristic(30))
        .clientAllowlist(ip -> ip.startsWith("10.0.0."))
        .build();

BotGuardEngine.Decision decision = engine.evaluate(
        new RequestSnapshot(clientIp, path, userAgent, headerNames, Instant.now()));

if (decision.verdict() == Verdict.BLOCK) { /* reject */ }
```

## Resource bounds

All state is in-process memory, bounded on three axes:

- **Per key per second**: request counters bucket events at 1-second
  granularity, so a flood from one client grows the bucket's count, not its
  memory.
- **Distinct paths per key**: scan detection caps the distinct values kept
  per key (default 10,000, configurable). Detection thresholds below the cap
  still see true counts; the cap stops memory growth during a scan flood.
- **Number of keys**: each counter keeps at most 100,000 distinct keys
  (configurable), evicting stale entries first and then least-recently-active
  ones. Under an extreme IP-spray that eviction can drop legitimate keys
  early; treat the bound as a safety net, not a guarantee of accuracy under
  attack.

Sizing and eviction are documented on `SlidingWindowCounter` and
`DistinctValueCounter`.

## Client identity and proxies

Rate rules are only as good as the key you feed them. By default the Spring
adapter uses the direct connection address. If your service sits behind a
proxy you control, you can resolve the client from `X-Forwarded-For`, but
only when your proxy overwrites that header - otherwise any client can spoof
its identity and bypass per-IP rules entirely. See `ClientIpResolver`.

## Spring Boot adapter (`botguard-spring-boot`)

A servlet filter targeting the Spring Boot 2.7-era javax servlet API. Register
it as a bean; it applies the engine and returns 403 for `BLOCK`, 429 for
`CHALLENGE` (override `onChallenge` for captcha or throttling).

Tested so far: the filter's verdict mapping, allowlist behavior, and
client-IP resolution are unit-tested against a stubbed servlet API. It has
not yet been run inside a live Spring Boot application, and there is no
auto-configuration yet - you wire the filter yourself.

```java
@Bean
FilterRegistrationBean<BotGuardFilter> botguard() {
    BotGuardEngine engine = BotGuardEngine.builder()
            .addRule(RateRule.perClientIp(60, Duration.ofMinutes(1)))
            .addHeuristic(new UserAgentHeuristic())
            .build();
    FilterRegistrationBean<BotGuardFilter> reg = new FilterRegistrationBean<>(
            // direct() ignores forwarding headers; see "Client identity and proxies"
            new BotGuardFilter(engine, ClientIpResolver.direct()));
    reg.addUrlPatterns("/*");
    return reg;
}
```

Auto-configuration (`@EnableAutoConfiguration` + properties) is planned; for
v0.1 you wire the filter yourself.

## Modules

- `botguard-core` - framework-independent engine, Java 11+, zero dependencies.
- `botguard-spring-boot` - servlet filter adapter (Spring Boot 2.7, javax).

## Building and testing

Build with `./gradlew build` (needs a JDK 11+ toolchain). The repo includes
the wrapper scripts (`gradlew`, `gradlew.bat`) and
`gradle/wrapper/gradle-wrapper.properties`; the small `gradle-wrapper.jar`
bootstrap is not committed yet, so the first build needs a local Gradle
install (`gradle wrapper` regenerates the jar) or the jar copied from any
Gradle 8.10 distribution. With any Gradle 8.x installed, `gradle build`
also works directly.

The test suite (20 tests) covers the engine's verdict logic, window eviction,
key-space and per-key bounds under adversarial floods, concurrency, and the
servlet filter's verdict mapping against a stubbed servlet API. It is a
starting point, not proof of correctness in production.

## Publishing

The Gradle build produces JARs, sources, and javadoc with Maven Central-ready
POM metadata. No remote repository or signing is configured yet; publishing to
Maven Central requires adding a Sonatype Central Portal repository and signing
credentials, which has not been done.

## Roadmap / contributing

Ideas for first contributions: Spring Boot auto-configuration, persistent or
shared counters (e.g. Redis) for multi-instance deployments, challenge
integrations (captcha), and heuristics tuned from real traffic data. Issues
and PRs welcome - honest measurements of false-positive rates are especially
valuable.

## License

Apache License 2.0 (proposed). See [LICENSE](LICENSE).
