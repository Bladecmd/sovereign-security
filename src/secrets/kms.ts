/**
 * Sovereign Security — Milestone V0.4
 * Hardware Security Module (HSM) / KMS Envelope Encryption Engine
 *
 * Implements envelope encryption where data is encrypted using an ephemeral
 * Data Encryption Key (DEK) via AES-256-GCM, and the DEK is wrapped by a master
 * Key Encryption Key (KEK) managed under KMS/HSM governance.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { KMSEnvelope, KMSMasterKeyDescriptor } from '../types/secrets.js';

export class KMSKeyManager {
  private masterKeys: Map<string, { descriptor: KMSMasterKeyDescriptor; rawKey: Buffer }> =
    new Map();

  constructor() {
    this.createMasterKey('default-master-kek', 'Default Sovereign KMS Key');
  }

  /**
   * Provision a new master key encryption key (KEK)
   */
  public createMasterKey(keyId: string, alias: string): KMSMasterKeyDescriptor {
    const rawKey = randomBytes(32); // 256-bit master key
    const descriptor: KMSMasterKeyDescriptor = {
      keyId,
      alias,
      state: 'ACTIVE',
      algorithm: 'AES-256-GCM',
      createdAt: new Date().toISOString(),
      lastRotatedAt: new Date().toISOString(),
    };

    this.masterKeys.set(keyId, { descriptor, rawKey });
    return descriptor;
  }

  /**
   * Encrypt data using an ephemeral Data Encryption Key (DEK) wrapped under the master KEK
   */
  public encryptEnvelope(plaintext: string, masterKeyId = 'default-master-kek'): KMSEnvelope {
    const master = this.masterKeys.get(masterKeyId);
    if (!master || master.descriptor.state !== 'ACTIVE') {
      throw new Error(`Master KEK '${masterKeyId}' is not available or inactive.`);
    }

    // 1. Generate ephemeral DEK (32 bytes)
    const dek = randomBytes(32);
    const iv = randomBytes(12); // 96-bit standard GCM IV

    // 2. Encrypt plaintext payload with DEK using AES-256-GCM
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    let ciphertext = cipher.update(plaintext, 'utf-8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // 3. Wrap DEK under Master KEK using AES-256-GCM
    const wrapIv = randomBytes(12);
    const wrapCipher = createCipheriv('aes-256-gcm', master.rawKey, wrapIv);
    let wrappedDek = wrapCipher.update(dek.toString('hex'), 'utf-8', 'hex');
    wrappedDek += wrapCipher.final('hex');
    const wrapTag = wrapCipher.getAuthTag().toString('hex');

    // Pack wrapIv + wrapTag + wrappedDek into composite wrappedDataKey string
    const wrappedDataKey = `${wrapIv.toString('hex')}:${wrapTag}:${wrappedDek}`;

    return {
      keyId: masterKeyId,
      keyVersion: 1,
      algorithm: 'AES-256-GCM',
      iv: iv.toString('hex'),
      authTag,
      wrappedDataKey,
      ciphertext,
    };
  }

  /**
   * Decrypt envelope: unwrap ephemeral DEK using Master KEK, then decrypt payload
   */
  public decryptEnvelope(envelope: KMSEnvelope): string {
    const master = this.masterKeys.get(envelope.keyId);
    if (!master || master.descriptor.state === 'DESTROYED') {
      throw new Error(`Master KEK '${envelope.keyId}' is destroyed or missing.`);
    }

    // 1. Unwrap DEK
    const [wrapIvHex, wrapTagHex, encDekHex] = envelope.wrappedDataKey.split(':');
    if (!wrapIvHex || !wrapTagHex || !encDekHex) {
      throw new Error('Malformed wrappedDataKey in KMSEnvelope.');
    }

    const unwrapDecipher = createDecipheriv(
      'aes-256-gcm',
      master.rawKey,
      Buffer.from(wrapIvHex, 'hex')
    );
    unwrapDecipher.setAuthTag(Buffer.from(wrapTagHex, 'hex'));
    let dekHex = unwrapDecipher.update(encDekHex, 'hex', 'utf-8');
    dekHex += unwrapDecipher.final('utf-8');
    const dek = Buffer.from(dekHex, 'hex');

    // 2. Decrypt Payload
    const payloadDecipher = createDecipheriv(
      'aes-256-gcm',
      dek,
      Buffer.from(envelope.iv, 'hex')
    );
    payloadDecipher.setAuthTag(Buffer.from(envelope.authTag, 'hex'));
    let decrypted = payloadDecipher.update(envelope.ciphertext, 'hex', 'utf-8');
    decrypted += payloadDecipher.final('utf-8');

    return decrypted;
  }

  /**
   * Destroy a master key (cryptographic shredding)
   */
  public destroyMasterKey(keyId: string): void {
    const master = this.masterKeys.get(keyId);
    if (master) {
      master.rawKey.fill(0); // Overwrite memory
      master.descriptor.state = 'DESTROYED';
    }
  }
}
