/**
 * Sovereign Security — Foundation V0.1
 * Core Package Entry Point
 *
 * Independent Identity, Security, Risk, and Governance Layer
 */

// Types & Contracts
export * from './types/events.js';
export * from './types/alerts.js';
export * from './types/identity.js';
export * from './types/policy.js';
export * from './types/ai-security.js';
export * from './types/audit.js';
export * from './types/secrets.js';
export * from './types/observability.js';

// Runtime Zod Schemas & Validation
export * from './schemas/event.schema.js';
export * from './schemas/alert.schema.js';
export * from './schemas/policy.schema.js';

// Identity & Access Management (RBAC, ABAC, JIT, WebAuthn, Tenant)
export * from './identity/rbac.js';
export * from './identity/abac.js';
export * from './identity/jit.js';
export * from './identity/webauthn.js';
export * from './identity/tenant.js';

// Policy Engine
export * from './policy/engine.js';

// AI Security Pipeline & Tool Permissions
export * from './ai/pipeline.js';
export * from './ai/tool-permissions.js';

// Threat & Risk Engines
export * from './threat/engine.js';
export * from './risk/engine.js';

// Audit Foundation
export * from './audit/audit-service.js';

// Secrets Security (Detection, Scanner, Rotation, KMS, Git Hooks)
export * from './secrets/detector.js';
export * from './secrets/scanner.js';
export * from './secrets/rotation-orchestrator.js';
export * from './secrets/kms.js';
export * from './secrets/git-hook.js';

// Observability
export * from './observability/logger.js';

// Integration Adapters
export * from './integrations/sovereign-os/client.js';
export * from './integrations/mtf/adapter.js';

// Local Mock HTTP Server
export * from './server/routes.js';
export * from './server/server.js';

// Software Supply Chain & Vulnerability Intelligence
export * from './types/supply-chain.js';
export * from './supply-chain/sbom.js';
export * from './supply-chain/cve-scanner.js';
export * from './supply-chain/slsa.js';
export * from './supply-chain/license.js';

// AI Security Gateway (Milestone V0.6)
export * from './types/ai-gateway.js';
export * from './ai/gateway.js';
export * from './ai/prompt-injection.js';
export * from './ai/model-armor.js';
export * from './ai/agent-sandbox.js';
export * from './ai/grounding.js';

// Autonomous Security Agents (Milestone V0.7)
export * from './types/agents.js';
export * from './agents/sentinel.js';
export * from './agents/containment.js';
export * from './agents/forensics.js';
export * from './agents/coordinator.js';

// Integrated Sovereign Security Operations Platform (Milestone V1.0)
export * from './types/compliance.js';
export * from './compliance/frameworks.js';
export * from './compliance/certification.js';
export * from './posture/synchronizer.js';
export * from './platform/platform.js';

// Roadmap Markers
export * from './roadmap/markers.js';



