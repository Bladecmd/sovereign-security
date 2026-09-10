# Sovereign Security — Edge Security & Production Perimeter Architecture

**Document Version**: 1.1.0-RC  
**Classification**: Defensive Architecture Specification & Production Deployment Baseline  
**Scope**: Layer 3/4, Layer 7 Perimeter & Application-Layer Defense Boundaries

---

## 1. Executive Summary & Honest Security Boundaries

Sovereign Security is designed as a zero-trust, decoupled defensive security runtime and policy engine.

> **CRITICAL ARCHITECTURAL PRINCIPLE**:  
> **Application-layer controls CANNOT defend against volumetric network-layer DDoS attacks.**  
> Any software service running in Node.js, Go, Rust, or Java will exhaust socket descriptors, CPU interrupts, or network link capacity if subjected to multi-gigabit/terabit volumetric attacks (SYN floods, UDP reflection/amplification, ICMP saturations, or BGP route hijacking).

Sovereign Security's internal rate limiting (`ApplicationRateLimiter`) and request validation constitute an **in-depth identity- and business-logic-aware defense**, **NOT** the network perimeter boundary. Production deployments **MUST** front Sovereign Security with dedicated edge infrastructure.

---

## 2. Tiered Defense Topology

```
+-----------------------------------------------------------------------------+
|                         INTERNET / UNTRUSTED FLEET                          |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
| TIER 1: Volumetric & Edge Scrubbing (Cloudflare / Cloud Armor / AWS Shield)  |
| - Layer 3/4 DDoS Mitigation (Anycast BGP scrubbing)                         |
| - Geofencing & ASN Filtering                                                |
| - Edge TLS 1.3 Termination & SNI Validation                                |
| - Managed WAF Rules (OWASP Top 10, CRS 4.0, Bot Management)                 |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
| TIER 2: Reverse Proxy & Ingress Gateway (Envoy / NGINX / Traefik)           |
| - Mutual TLS (mTLS) with Ecosystem Fleet Nodes                             |
| - Coarse IP-level Leaky-Bucket Rate Limiting (1,000 req/s threshold)        |
| - Request Header Sanitization & Strict HTTP/2 Protocol Validation           |
| - Buffer Limits: 1MB Request Body Cap, 16KB Header Cap                      |
| - Upstream Connection Pooling & Keep-Alive Pooling                          |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
| TIER 3: Sovereign Security Runtime (Defense-in-Depth Core)                  |
| - Zero-Trust Cryptographic Verification (EcosystemAuthenticator)             |
| - Distributed Nonce Replay Protection (ReplayProtectionStore)               |
| - Identity-, Service-, & Endpoint-Aware Rate Limiting (ApplicationRateLimiter)|
| - Adversarial Prompt Injection & Delimiter Filtering (AISecurityGateway)    |
| - Deterministic Policy & Precedence Evaluation (PolicyEngine)                |
| - Cryptographic Security Decision Provenance & Audit Ledger (AuditService)   |
+-----------------------------------------------------------------------------+
```

---

## 3. Tier 1 Requirements: Volumetric & Cloud Perimeter Scrubbing

Production deployments must terminate public traffic through an enterprise Anycast scrubbing provider:

- **Supported Platforms**: Cloudflare Magic Transit / Enterprise, AWS Shield Advanced + CloudFront, Google Cloud Armor + Global External HTTP(S) Load Balancer.
- **Network Layer Controls**:
  - Immediate packet dropping for non-TCP traffic outside established tunnels.
  - SYN flood mitigation via SYN cookies at the Anycast edge.
  - Automated detection and rate-limiting of high-entropy UDP bursts.
- **Web Application Firewall (WAF)**:
  - OWASP Core Rule Set (CRS) 4.0 in blocking mode (anomaly score threshold $\le 5$).
  - Malformed HTTP protocol anomaly rules enabled.
  - Bot score threshold blocking (e.g. Cloudflare Bot Score $< 20$ dropped).

---

## 4. Tier 2 Requirements: Ingress Reverse Proxy & Load Balancer

Between the scrubbing edge and the Sovereign Security runtime, a dedicated reverse proxy (Envoy or NGINX) must enforce:

### 4.1. Cryptographic & Protocol Termination
- **Protocol**: HTTP/2 or HTTP/3 exclusively. Unencrypted HTTP/1.0 and HTTP/1.1 without TLS must be rejected at the socket.
- **TLS Configuration**:
  - TLS 1.3 mandatory; TLS 1.2 allowed only with AEAD ciphers (`ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`).
  - Strict Transport Security (`HSTS`): `max-age=63072000; includeSubDomains; preload`.
  - Disable session tickets or cycle keys every 3,600 seconds.

### 4.2. Request Sizing & Buffer Constraints
- **Maximum Header Size**: 16 KB.
- **Maximum Request Body Size**: 1 MB (matching Sovereign Security's internal limit). Requests exceeding 1 MB must return HTTP 413 at the proxy level without saturating Node.js memory.
- **Timeout Quotas**:
  - Client header timeout: 5s
  - Client body read timeout: 10s
  - Upstream response timeout: 30s
  - Idle keep-alive timeout: 60s

### 4.3. Coarse Ingress Rate Limiting
- Leaky bucket at the proxy layer: 500 requests/second per source `/24` IPv4 or `/48` IPv6 subnet.
- Rejection status: HTTP 429 with `Retry-After` header.

---

## 5. Tier 3: Sovereign Security Defense-in-Depth Responsibility

Sovereign Security operates under the assumption that network-level floods are scrubbed at Tiers 1 & 2. Sovereign Security's internal defenses provide:

1. **Identity-Bound Rate Limiting**:
   - Tracking authenticating entities (`sovereign-os`, `metro-task-force`, `compliance-labs`, `audioblue`, `gridd-corp`) rather than raw IP addresses, preventing distributed credential abuse.
2. **Endpoint-Aware Quotas**:
   - Strict limits for high-impact operations (`/api/v1/agents/containment`, `/api/v1/policy/rules`).
3. **Application Replay Protection**:
   - Atomic nonce check-and-set preventing semantic replays within a 5-minute clock skew window.
4. **Adversarial Payload Sanitization**:
   - Deep inspection of ChatML markers, indirect prompt injections, and tool privilege escalation vectors.
5. **Fail-Closed Resilience**:
   - If distributed state backends (e.g. Redis cluster) fail, authentication and authorization fail closed, preserving security posture under infrastructure degradation.

---

## 6. Verification & Operational Runbooks

- **Penetration Testing**: Validate that synthetic volumetric SYN and UDP reflection attacks are stopped entirely by Tier 1 before reaching Tier 2 ingress IP addresses.
- **Proxy Load Testing**: Validate that HTTP request floods with payloads $> 1\text{ MB}$ return HTTP 413 directly from Envoy/NGINX without increasing Node.js event loop latency.
- **Application Validation**: Execute `npm test` verifying that `tests/rate-limiting.test.ts` and `tests/distributed-replay.test.ts` pass all deterministic failure and burst conditions.
