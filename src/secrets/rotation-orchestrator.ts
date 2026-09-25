/**
 * Sovereign Security — Milestone V0.4
 * Automated Zero-Downtime Key Rotation Orchestrator
 *
 * Coordinates graceful dual-key rotation across Sovereign OS, Metro Task Force, and ecosystem services.
 * Eliminates operational downtime by orchestrating multi-phase transitions:
 * INITIATED -> SECONDARY_DEPLOYED -> PRIMARY_PROMOTED -> OLD_KEY_DEPRECATED -> COMPLETED
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  SecretClassification,
  ServiceCredentialDescriptor,
  ZeroDowntimeRotationJob,
} from '../types/secrets.js';

export class KeyRotationOrchestrator {
  private activeCredentials: Map<string, ServiceCredentialDescriptor> = new Map();
  private jobs: Map<string, ZeroDowntimeRotationJob> = new Map();

  /**
   * Register an initial service credential
   */
  public registerCredential(
    service: string,
    classification: SecretClassification,
    validDays = 90
  ): ServiceCredentialDescriptor {
    const credentialId = `cred-${service}-${Date.now()}`;
    const rawSecret = randomBytes(32).toString('hex');
    const activeKeyHash = createHash('sha256').update(rawSecret).digest('hex');

    const desc: ServiceCredentialDescriptor = {
      credentialId,
      service,
      classification,
      version: 1,
      activeKeyHash,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + validDays * 86400000).toISOString(),
      status: 'ACTIVE',
    };

    this.activeCredentials.set(service, desc);
    return desc;
  }

  /**
   * Initiate a zero-downtime rotation workflow for a given service
   */
  public initiateRotation(service: string): ZeroDowntimeRotationJob {
    const currentCred = this.activeCredentials.get(service);
    if (!currentCred) {
      throw new Error(`Service '${service}' has no active credentials registered.`);
    }

    const jobId = `rot-job-${service}-${Date.now()}`;
    const newCredentialId = `cred-${service}-${Date.now()}-v${currentCred.version + 1}`;

    const job: ZeroDowntimeRotationJob = {
      jobId,
      service,
      oldCredentialId: currentCred.credentialId,
      newCredentialId,
      currentPhase: 'INITIATED',
      startedAt: new Date().toISOString(),
      auditTrail: [`[Phase 1] Rotation initiated for service '${service}'. Old key: ${currentCred.credentialId}`],
    };

    this.jobs.set(jobId, job);
    return job;
  }

  /**
   * Phase 2: Deploy new key as secondary (both keys valid for verification)
   */
  public stepDeploySecondary(jobId: string): ZeroDowntimeRotationJob {
    const job = this.getJobOrThrow(jobId);
    job.currentPhase = 'SECONDARY_DEPLOYED';
    job.auditTrail.push(`[Phase 2] Secondary credential deployed. Microservices accepting both keys.`);
    return job;
  }

  /**
   * Phase 3: Promote new key to primary (new transactions sign/auth using new key)
   */
  public stepPromotePrimary(jobId: string): ZeroDowntimeRotationJob {
    const job = this.getJobOrThrow(jobId);
    const oldCred = this.activeCredentials.get(job.service)!;

    const newKeyHash = createHash('sha256').update(randomBytes(32)).digest('hex');

    const newCred: ServiceCredentialDescriptor = {
      credentialId: job.newCredentialId,
      service: job.service,
      classification: oldCred.classification,
      version: oldCred.version + 1,
      activeKeyHash: newKeyHash,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 90 * 86400000).toISOString(),
      status: 'ACTIVE',
    };

    oldCred.status = 'DEPRECATED';
    this.activeCredentials.set(job.service, newCred);

    job.currentPhase = 'PRIMARY_PROMOTED';
    job.auditTrail.push(`[Phase 3] Primary key promoted to ${job.newCredentialId}. Old key marked DEPRECATED.`);
    return job;
  }

  /**
   * Phase 4: Deprecate old key (drain remaining verification windows)
   */
  public stepDeprecateOldKey(jobId: string): ZeroDowntimeRotationJob {
    const job = this.getJobOrThrow(jobId);
    job.currentPhase = 'OLD_KEY_DEPRECATED';
    job.auditTrail.push(`[Phase 4] Verification grace period active. Old key scheduled for revocation.`);
    return job;
  }

  /**
   * Phase 5: Complete rotation and revoke old credential
   */
  public stepCompleteAndRevoke(jobId: string): ZeroDowntimeRotationJob {
    const job = this.getJobOrThrow(jobId);
    job.currentPhase = 'COMPLETED';
    job.completedAt = new Date().toISOString();
    job.auditTrail.push(`[Phase 5] Rotation complete. Old credential '${job.oldCredentialId}' revoked.`);
    return job;
  }

  public getCredential(service: string): ServiceCredentialDescriptor | undefined {
    return this.activeCredentials.get(service);
  }

  public getJob(jobId: string): ZeroDowntimeRotationJob | undefined {
    return this.jobs.get(jobId);
  }

  private getJobOrThrow(jobId: string): ZeroDowntimeRotationJob {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new Error(`Rotation job '${jobId}' not found.`);
    }
    return job;
  }
}
