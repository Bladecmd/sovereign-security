/**
 * Sovereign Security — Foundation V0.1
 * Observability & Structured Logging Types
 */

export interface StructuredLogEntry {
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  requestId: string;
  service: string;
  operation: string;
  durationMs?: number;
  result: 'SUCCESS' | 'FAILURE' | 'PENDING';
  failure?: {
    code: string;
    message: string;
    stack?: string;
  };
  correlationId: string;
  metadata?: Record<string, unknown>;
}

export interface LoggerOptions {
  serviceName: string;
  minLevel?: 'debug' | 'info' | 'warn' | 'error';
  redactKeys?: string[];
}
