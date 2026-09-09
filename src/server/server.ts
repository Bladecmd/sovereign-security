/**
 * Sovereign Security — Foundation V0.1
 * Local HTTP Mock API Server
 *
 * Runs a standalone HTTP daemon allowing Sovereign OS, MTF, and other local services
 * to emit live webhooks and query security policies.
 */

import { createServer, Server } from 'node:http';
import { StructuredLogger } from '../observability/logger.js';
import { SovereignSecurityApiHandler } from './routes.js';

export interface ServerConfig {
  port?: number;
  host?: string;
}

export function startSovereignSecurityServer(config: ServerConfig = {}): Promise<{
  server: Server;
  port: number;
  stop: () => Promise<void>;
}> {
  const port = config.port || Number(process.env.PORT) || 4000;
  const host = config.host || '127.0.0.1';

  const logger = new StructuredLogger({
    serviceName: 'sovereign-security-server',
    minLevel: 'info',
  });

  const handler = new SovereignSecurityApiHandler({ logger });

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

// Direct CLI invocation
if (process.argv[1]?.endsWith('server.ts') || process.argv[1]?.endsWith('server.js')) {
  startSovereignSecurityServer().then(({ port }) => {
    console.log(`[Sovereign Security API] Live on http://127.0.0.1:${port}`);
    console.log(`[Sovereign Security API] Health check: http://127.0.0.1:${port}/health`);
  });
}
