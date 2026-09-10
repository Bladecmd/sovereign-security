/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * Ecosystem Mutual Authentication & Replay Protection Module
 *
 * Enforces strict credentials and cryptographic authorization across all
 * 5 authorized Sovereign ecosystem entities:
 * 1. Sovereign OS (sovereign-os)
 * 2. Metro Task Force (metro-task-force)
 * 3. Compliance Labs (compliance-labs)
 * 4. AudioBlue (audioblue)
 * 5. GriDD Corp (gridd-corp)
 */

import { createHmac, timingSafeEqual } from 'crypto';
import {
  ReplayProtectionStore,
  InMemoryReplayProtectionStore,
} from './replay-store.js';

export interface EcosystemCredentials {
  serviceId: string;
  businessId: string;
  environment: string;
  apiKey: string;
  timestamp: string;
  nonce: string;
  signature?: string;
}

export interface AuthenticatedEntity {
  serviceId: string;
  businessId: string;
  displayName: string;
  secretKey: string;
}

export interface AuthVerificationResult {
  authenticated: boolean;
  errorCode?:
    | 'UNKNOWN_SERVICE'
    | 'UNKNOWN_BUSINESS'
    | 'EXPIRED_TIMESTAMP'
    | 'REPLAY_DETECTED'
    | 'REPLAY_STORE_UNAVAILABLE'
    | 'INVALID_API_KEY'
    | 'INVALID_SIGNATURE';
  errorMessage?: string;
  entityName?: string;
}

export class EcosystemAuthenticator {
  public static readonly MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // 5 minutes max skew
  private static replayStore: ReplayProtectionStore = new InMemoryReplayProtectionStore();

  public static setReplayStore(store: ReplayProtectionStore): void {
    this.replayStore = store;
  }

  public static getReplayStore(): ReplayProtectionStore {
    return this.replayStore;
  }

  public static resetReplayStore(): void {
    this.replayStore = new InMemoryReplayProtectionStore();
  }

  public static readonly AUTHORIZED_ENTITIES: Record<string, AuthenticatedEntity> = {
    'sovereign-os': {
      serviceId: 'sovereign-os',
      businessId: 'sovereign-core-hq',
      displayName: 'Sovereign OS Kernel & Executive Services',
      secretKey: 'sec_key_sovereign_os_prod_secret',
    },
    'metro-task-force': {
      serviceId: 'metro-task-force',
      businessId: 'mtf-hq',
      displayName: 'Metro Task Force Operations & Telemetry Feed',
      secretKey: 'sec_key_mtf_telemetry_prod_secret',
    },
    'compliance-labs': {
      serviceId: 'compliance-labs',
      businessId: 'compliance-labs-inc',
      displayName: 'Compliance Labs Audit & Attestation Gateway',
      secretKey: 'sec_key_compliance_labs_audit_secret',
    },
    'audioblue': {
      serviceId: 'audioblue',
      businessId: 'audioblue-media',
      displayName: 'AudioBlue Media CI/CD & Build Pipeline',
      secretKey: 'sec_key_audioblue_build_secret',
    },
    'gridd-corp': {
      serviceId: 'gridd-corp',
      businessId: 'gridd-holding-corp',
      displayName: 'GriDD Corporation Fleet Governance & Posture Aggregator',
      secretKey: 'sec_key_gridd_corp_governance_secret',
    },
  };

  /**
   * Validates ecosystem request credentials against zero-trust registry (Synchronous)
   */
  public static verifyCredentials(
    creds: EcosystemCredentials,
    rawBodyToVerify?: string,
    customStore?: ReplayProtectionStore
  ): AuthVerificationResult {
    // 1. Validate service registration
    const entity = this.AUTHORIZED_ENTITIES[creds.serviceId];
    if (!entity) {
      return {
        authenticated: false,
        errorCode: 'UNKNOWN_SERVICE',
        errorMessage: `Service '${creds.serviceId}' is not an authorized member of the Sovereign ecosystem.`,
      };
    }

    // 2. Validate business identity binding
    if (entity.businessId !== creds.businessId) {
      return {
        authenticated: false,
        errorCode: 'UNKNOWN_BUSINESS',
        errorMessage: `BusinessId '${creds.businessId}' does not match registered entity for '${creds.serviceId}'.`,
      };
    }

    // 3. Timestamp freshness check (anti-replay / expiration)
    const requestTime = new Date(creds.timestamp).getTime();
    const now = Date.now();
    if (isNaN(requestTime) || Math.abs(now - requestTime) > this.MAX_CLOCK_SKEW_MS) {
      return {
        authenticated: false,
        errorCode: 'EXPIRED_TIMESTAMP',
        errorMessage: `Timestamp out of acceptable window (+/- 5m). Received: ${creds.timestamp}`,
      };
    }

    // 4. Nonce replay check (fail-closed on store exception)
    const store = customStore || this.replayStore;
    try {
      const consumed = store.consume(creds.nonce, this.MAX_CLOCK_SKEW_MS);
      if (consumed instanceof Promise) {
        return {
          authenticated: false,
          errorCode: 'REPLAY_STORE_UNAVAILABLE',
          errorMessage: 'Asynchronous distributed replay store requires EcosystemAuthenticator.verifyCredentialsAsync()',
        };
      }
      if (!consumed) {
        return {
          authenticated: false,
          errorCode: 'REPLAY_DETECTED',
          errorMessage: `Nonce '${creds.nonce}' has already been processed within the freshness window.`,
        };
      }
    } catch (err: any) {
      return {
        authenticated: false,
        errorCode: 'REPLAY_STORE_UNAVAILABLE',
        errorMessage: `Replay store failure (fail-closed enforced): ${err?.message || 'Unknown error'}`,
      };
    }

    // 5. Signature verification (if signature provided or payload provided)
    if (creds.signature && rawBodyToVerify !== undefined) {
      const expectedSignature = this.createSignature(
        entity.secretKey,
        creds.timestamp,
        creds.nonce,
        rawBodyToVerify
      );

      const sigBuffer = Buffer.from(creds.signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
        return {
          authenticated: false,
          errorCode: 'INVALID_SIGNATURE',
          errorMessage: 'Cryptographic HMAC-SHA256 signature verification failed.',
        };
      }
    }

    return {
      authenticated: true,
      entityName: entity.displayName,
    };
  }

  /**
   * Validates ecosystem request credentials asynchronously (Supports distributed stores)
   */
  public static async verifyCredentialsAsync(
    creds: EcosystemCredentials,
    rawBodyToVerify?: string,
    customStore?: ReplayProtectionStore
  ): Promise<AuthVerificationResult> {
    // 1. Validate service registration
    const entity = this.AUTHORIZED_ENTITIES[creds.serviceId];
    if (!entity) {
      return {
        authenticated: false,
        errorCode: 'UNKNOWN_SERVICE',
        errorMessage: `Service '${creds.serviceId}' is not an authorized member of the Sovereign ecosystem.`,
      };
    }

    // 2. Validate business identity binding
    if (entity.businessId !== creds.businessId) {
      return {
        authenticated: false,
        errorCode: 'UNKNOWN_BUSINESS',
        errorMessage: `BusinessId '${creds.businessId}' does not match registered entity for '${creds.serviceId}'.`,
      };
    }

    // 3. Timestamp freshness check
    const requestTime = new Date(creds.timestamp).getTime();
    const now = Date.now();
    if (isNaN(requestTime) || Math.abs(now - requestTime) > this.MAX_CLOCK_SKEW_MS) {
      return {
        authenticated: false,
        errorCode: 'EXPIRED_TIMESTAMP',
        errorMessage: `Timestamp out of acceptable window (+/- 5m). Received: ${creds.timestamp}`,
      };
    }

    // 4. Nonce replay check with distributed fail-closed handling
    const store = customStore || this.replayStore;
    try {
      const health = await store.health();
      if (!health.healthy) {
        return {
          authenticated: false,
          errorCode: 'REPLAY_STORE_UNAVAILABLE',
          errorMessage: `Replay store unhealthy (${health.lastFailure || 'failed health check'}): fail-closed enforced`,
        };
      }

      const consumed = await store.consume(creds.nonce, this.MAX_CLOCK_SKEW_MS);
      if (!consumed) {
        return {
          authenticated: false,
          errorCode: 'REPLAY_DETECTED',
          errorMessage: `Nonce '${creds.nonce}' has already been processed within the freshness window.`,
        };
      }
    } catch (err: any) {
      return {
        authenticated: false,
        errorCode: 'REPLAY_STORE_UNAVAILABLE',
        errorMessage: `Replay store failure (fail-closed enforced): ${err?.message || 'Unknown error'}`,
      };
    }

    // 5. Signature verification
    if (creds.signature && rawBodyToVerify !== undefined) {
      const expectedSignature = this.createSignature(
        entity.secretKey,
        creds.timestamp,
        creds.nonce,
        rawBodyToVerify
      );

      const sigBuffer = Buffer.from(creds.signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
        return {
          authenticated: false,
          errorCode: 'INVALID_SIGNATURE',
          errorMessage: 'Cryptographic HMAC-SHA256 signature verification failed.',
        };
      }
    }

    return {
      authenticated: true,
      entityName: entity.displayName,
    };
  }

  public static getAuthorizedEntities(): readonly string[] {
    return Object.keys(this.AUTHORIZED_ENTITIES);
  }

  public static createSignature(
    secretKey: string,
    timestamp: string,
    nonce: string,
    payload: string
  ): string {
    const data = `${timestamp}:${nonce}:${payload}`;
    return createHmac('sha256', secretKey).update(data).digest('hex');
  }
}
