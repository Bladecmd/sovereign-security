/**
 * Sovereign Security — Foundation V0.2
 * Server-Sent Events (SSE) Live Telemetry Broadcaster
 *
 * Broadcasts real-time security events and alerts to connected dashboard clients.
 */

import { ServerResponse } from 'node:http';
import { SecurityAlert } from '../types/alerts.js';
import { SecurityEvent } from '../types/events.js';

export interface SSEMessage {
  type: 'EVENT' | 'ALERT' | 'AUDIT' | 'PING';
  data: unknown;
  timestamp: string;
}

export class TelemetryBroadcaster {
  private clients: Set<ServerResponse> = new Set();
  private heartbeatInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.startHeartbeat();
  }

  /**
   * Register a new SSE subscriber connection
   */
  public addClient(res: ServerResponse): void {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    res.write(`data: ${JSON.stringify({ type: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);
    this.clients.add(res);

    res.on('close', () => {
      this.clients.delete(res);
    });
  }

  /**
   * Broadcast a SecurityEvent to all active dashboard clients
   */
  public broadcastEvent(event: SecurityEvent): void {
    this.broadcast({
      type: 'EVENT',
      data: event,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Broadcast a SecurityAlert to all active dashboard clients
   */
  public broadcastAlert(alert: SecurityAlert): void {
    this.broadcast({
      type: 'ALERT',
      data: alert,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Close all active client connections and stop heartbeat
   */
  public shutdown(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    for (const client of this.clients) {
      client.end();
    }
    this.clients.clear();
  }

  public getSubscriberCount(): number {
    return this.clients.size;
  }

  private broadcast(msg: SSEMessage): void {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch {
        this.clients.delete(client);
      }
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.broadcast({
        type: 'PING',
        data: { activeSubscribers: this.clients.size },
        timestamp: new Date().toISOString(),
      });
    }, 15000);
    // Do not hold Node process open solely for heartbeat
    this.heartbeatInterval.unref();
  }
}
