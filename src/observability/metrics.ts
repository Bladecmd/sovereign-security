/**
 * Sovereign Security — Milestone Phase 2A
 * Production Prometheus Telemetry Exporter & Performance Metrics
 */

export interface MetricLabels {
  [key: string]: string | number;
}

export class MetricsRegistry {
  private counters: Map<string, { value: number; help: string; labelsMap: Map<string, number> }> = new Map();
  private gauges: Map<string, { value: number; help: string; labelsMap: Map<string, number> }> = new Map();
  private histograms: Map<string, { help: string; buckets: number[]; observations: { le: number; count: number }[]; sum: number; count: number }> = new Map();

  constructor() {
    this.initDefaultMetrics();
  }

  private initDefaultMetrics(): void {
    this.registerCounter('sovereign_policy_evaluations_total', 'Total number of policy evaluations performed');
    this.registerCounter('sovereign_policy_decisions_total', 'Total policy decisions broken down by outcome');
    this.registerCounter('sovereign_security_events_ingested_total', 'Total number of security events ingested');
    this.registerCounter('sovereign_security_alerts_generated_total', 'Total security alerts raised');
    this.registerCounter('sovereign_containment_quarantines_total', 'Total containment quarantines executed');
    this.registerCounter('sovereign_containment_releases_total', 'Total containment quarantines released');
    this.registerCounter('sovereign_audit_records_persisted_total', 'Total audit records persisted to tamper-evident ledger');

    this.registerGauge('sovereign_active_quarantines', 'Number of currently active quarantines');
    this.registerGauge('sovereign_audit_ledger_records', 'Total records in audit ledger');
    this.registerGauge('sovereign_audit_ledger_integrity_status', '1 if audit ledger cryptographic hash chain is valid, 0 if compromised');
    this.registerGauge('sovereign_process_uptime_seconds', 'Process uptime in seconds');
    this.registerGauge('sovereign_process_memory_heap_bytes', 'Process heap memory used in bytes');

    this.registerHistogram(
      'sovereign_policy_evaluation_duration_ms',
      'Policy evaluation latency in milliseconds',
      [0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500]
    );
  }

  public registerCounter(name: string, help: string): void {
    if (!this.counters.has(name)) {
      this.counters.set(name, { value: 0, help, labelsMap: new Map() });
    }
  }

  public registerGauge(name: string, help: string): void {
    if (!this.gauges.has(name)) {
      this.gauges.set(name, { value: 0, help, labelsMap: new Map() });
    }
  }

  public registerHistogram(name: string, help: string, buckets: number[]): void {
    if (!this.histograms.has(name)) {
      const sortedBuckets = [...buckets].sort((a, b) => a - b);
      this.histograms.set(name, {
        help,
        buckets: sortedBuckets,
        observations: sortedBuckets.map((b) => ({ le: b, count: 0 })),
        sum: 0,
        count: 0,
      });
    }
  }

  public incrementCounter(name: string, value: number = 1, labels?: MetricLabels): void {
    const counter = this.counters.get(name);
    if (!counter) return;
    counter.value += value;

    if (labels) {
      const key = this.formatLabels(labels);
      const current = counter.labelsMap.get(key) || 0;
      counter.labelsMap.set(key, current + value);
    }
  }

  public setGauge(name: string, value: number, labels?: MetricLabels): void {
    const gauge = this.gauges.get(name);
    if (!gauge) return;
    gauge.value = value;

    if (labels) {
      const key = this.formatLabels(labels);
      gauge.labelsMap.set(key, value);
    }
  }

  public observeHistogram(name: string, value: number): void {
    const hist = this.histograms.get(name);
    if (!hist) return;
    hist.count += 1;
    hist.sum += value;
    for (const obs of hist.observations) {
      if (value <= obs.le) {
        obs.count += 1;
      }
    }
  }

  private formatLabels(labels: MetricLabels): string {
    const entries = Object.entries(labels).map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`);
    return entries.length > 0 ? `{${entries.join(',')}}` : '';
  }

  public toPrometheusString(): string {
    const lines: string[] = [];
    this.setGauge('sovereign_process_uptime_seconds', Math.floor(process.uptime()));
    this.setGauge('sovereign_process_memory_heap_bytes', process.memoryUsage().heapUsed);

    for (const [name, data] of this.counters.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} counter`);
      if (data.labelsMap.size > 0) {
        for (const [lbl, val] of data.labelsMap.entries()) {
          lines.push(`${name}${lbl} ${val}`);
        }
      } else {
        lines.push(`${name} ${data.value}`);
      }
    }

    for (const [name, data] of this.gauges.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} gauge`);
      if (data.labelsMap.size > 0) {
        for (const [lbl, val] of data.labelsMap.entries()) {
          lines.push(`${name}${lbl} ${val}`);
        }
      } else {
        lines.push(`${name} ${data.value}`);
      }
    }

    for (const [name, data] of this.histograms.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} histogram`);
      for (const obs of data.observations) {
        lines.push(`${name}_bucket{le="${obs.le}"} ${obs.count}`);
      }
      lines.push(`${name}_bucket{le="+Inf"} ${data.count}`);
      lines.push(`${name}_sum ${data.sum}`);
      lines.push(`${name}_count ${data.count}`);
    }

    return lines.join('\n') + '\n';
  }
}

export const globalMetrics = new MetricsRegistry();
