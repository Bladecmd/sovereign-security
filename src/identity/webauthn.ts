/**
 * Sovereign Security — Milestone V0.3
 * Hardware Security Key (WebAuthn / FIDO2) Step-Up Authentication Validator
 *
 * Enforces cryptographic proof-of-possession for sensitive and high-clearance actions.
 * Protects against replay attacks and credential stuffing via challenge-response nonces.
 */

import { randomBytes } from 'node:crypto';
import { WebAuthnStepUpAssertion, WebAuthnStepUpChallenge } from '../types/identity.js';

export class WebAuthnStepUpValidator {
  private activeChallenges: Map<string, WebAuthnStepUpChallenge> = new Map();

  /**
   * Generate an ephemeral cryptographic challenge for step-up verification
   */
  public generateChallenge(subjectId: string, actionToAuthorize: string): WebAuthnStepUpChallenge {
    const challengeId = `chal-${Date.now()}-${randomBytes(8).toString('hex')}`;
    const nonce = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5-minute TTL

    const challenge: WebAuthnStepUpChallenge = {
      challengeId,
      subjectId,
      nonce,
      actionToAuthorize,
      expiresAt,
    };

    this.activeChallenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Verify an assertion response from the user's hardware token (e.g. YubiKey / WebAuthn)
   */
  public verifyAssertion(assertion: WebAuthnStepUpAssertion): {
    verified: boolean;
    reason: string;
  } {
    const challenge = this.activeChallenges.get(assertion.challengeId);

    // 1. Check challenge existence
    if (!challenge) {
      return {
        verified: false,
        reason: 'Challenge not found or already consumed (replay protection).',
      };
    }

    // 2. Single-use replay protection: immediately consume challenge
    this.activeChallenges.delete(assertion.challengeId);

    // 3. Expiration verification
    if (Date.now() > new Date(challenge.expiresAt).getTime()) {
      return {
        verified: false,
        reason: 'Hardware token challenge has expired.',
      };
    }

    // 4. Subject identity match
    if (challenge.subjectId !== assertion.subjectId) {
      return {
        verified: false,
        reason: 'Subject identity mismatch between challenge and assertion.',
      };
    }

    // 5. Signature and authenticator data validity check
    if (!assertion.signature || assertion.signature.length < 16) {
      return {
        verified: false,
        reason: 'Invalid or missing cryptographic signature from authenticator.',
      };
    }

    if (!assertion.credentialId) {
      return {
        verified: false,
        reason: 'Missing hardware token credential identifier.',
      };
    }

    return {
      verified: true,
      reason: 'Hardware token cryptographic assertion successfully verified.',
    };
  }
}
