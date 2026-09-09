/**
 * Sovereign Security — Milestone Phase 2A
 * Local HTTP API Server & Production Daemon
 */

import { createServer, Server } from 'node:http';
import { StructuredLogger } from '../observability/logger.js';
import { PersistentAuditLedger } from '../audit/persistent-storage.js';
import { SovereignSecurityApiHandler } from './routes.js';

export interface ServerConfig {
  port?: number;
  host?: string;
  auditStoragePath?: string;
}

export function startSovereignSecurityServer(config: ServerConfig = {}): Promise<{
  server: Server;
  port: number;
  stop: () => Promise<void>;
}> {
  const port = config.port || Number(process.env.PORT) || 4000;
  const host = config.host || process.env.HOST || '127.0.0.1';
  const auditPath = config.auditStoragePath || process.env.AUDIT_STORAGE_PATH;

  const logger = new StructuredLogger({
    serviceName: 'sovereign-security-server',
    minLevel: 'info',
  });

  let persistentLedger: PersistentAuditLedger | undefined;
  if (auditPath) {
    persistentLedger = new PersistentAuditLedger(auditPath);
    persistentLedger.initialize();
  }

  const handler = new SovereignSecurityApiHandler({
    logger,
    persistentLedger,
  });

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      handler.handleRequest(req, res);
    });

    server.listen(port, host, () => {
      logger.info(
        'server-init',
        'start',
        'server-boot',
        'SUCCESS',
        { port, host, environment: process.env.NODE_ENV || 'development' }
      );
      resolve({
        server,
        port,
        stop: () =>
          new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });

    server.on('error', (err) => {
      logger.error('server-init', 'start', 'server-boot', err);
      reject(err);
    });
  });
}

if (process.argv[1]?.endsWith('server.ts') || process.argv[1]?.endsWith('server.js')) {
  startSovereignSecurityServer().then(({ port }) => {
    console.log(`[Sovereign Security API] Live on http://127.0.0.1:${port}`);
    console.log(`[Sovereign Security API] Health check: http://127.0.0.1:${port}/health`);
    console.log(`[Sovereign Security API] Readiness probe: http://127.0.0.1:${port}/ready`);
    console.log(`[Sovereign Security API] Prometheus Metrics: http://127.0.0.1:${port}/metrics`);
  });
}
