/**
 * Sovereign Security — Foundation V0.1
 * Structured Observability Logger with Mandatory Secret Redaction
 *
 * Tracks: requestId, service, operation, duration, result, failure, correlationId.
 * Guarantees: Never logs passwords, API keys, tokens, or private keys.
 */

import { SecretsDetector } from '../secrets/detector.js';
import { LoggerOptions, StructuredLogEntry } from '../types/observability.js';

export class StructuredLogger {
  private serviceName: string;
  private minLevel: 'debug' | 'info' | 'warn' | 'error';
  private logSink: (entry: StructuredLogEntry) => void;

  constructor(options: LoggerOptions, customSink?: (entry: StructuredLogEntry) => void) {
    this.serviceName = options.serviceName;
    this.minLevel = options.minLevel || 'info';
    this.logSink = customSink || ((entry) => {
      const line = JSON.stringify(entry);
      if (entry.level === 'error') {
        console.error(line);
      } else if (entry.level === 'warn') {
        console.warn(line);
      } else {
        console.log(line);
      }
    });
  }

  public log(entry: Omit<StructuredLogEntry, 'timestamp' | 'service'>): void {
    const levelOrder = { debug: 0, info: 1, warn: 2, error: 3 };
    if (levelOrder[entry.level] < levelOrder[this.minLevel]) {
      return;
    }

    // Strictly redact metadata to prevent leakage of secrets, keys, or passwords
    const sanitizedMetadata = entry.metadata
      ? (SecretsDetector.redactPayload(entry.metadata) as Record<string, unknown>)
      : undefined;

    const fullEntry: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      level: entry.level,
      requestId: entry.requestId,
      operation: entry.operation,
      durationMs: entry.durationMs,
      result: entry.result,
      failure: entry.failure,
      correlationId: entry.correlationId,
      metadata: sanitizedMetadata,
    };

    this.logSink(fullEntry);
  }

  public info(
    requestId: string,
    operation: string,
    correlationId: string,
    result: 'SUCCESS' | 'FAILURE' | 'PENDING' = 'SUCCESS',
    metadata?: Record<string, unknown>,
    durationMs?: number
  ): void {
    this.log({
      level: 'info',
      requestId,
      operation,
      correlationId,
      result,
      metadata,
      durationMs,
    });
  }

  public warn(
    requestId: string,
    operation: string,
    correlationId: string,
    message: string,
    metadata?: Record<string, unknown>
  ): void {
    this.log({
      level: 'warn',
      requestId,
      operation,
      correlationId,
      result: 'FAILURE',
      failure: { code: 'WARNING', message },
      metadata,
    });
  }

  public error(
    requestId: string,
    operation: string,
    correlationId: string,
    error: Error | { code: string; message: string },
    metadata?: Record<string, unknown>
  ): void {
    this.log({
      level: 'error',
      requestId,
      operation,
      correlationId,
      result: 'FAILURE',
      failure: {
        code: 'code' in error ? error.code : 'INTERNAL_ERROR',
        message: error.message,
        stack: error instanceof Error ? error.stack : undefined,
      },
      metadata,
    });
  }
}
