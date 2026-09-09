/**
 * Sovereign Security — Milestone V0.7
 * Autonomous Security Agent Coordinator
 */

import { AuditService } from '../audit/audit-service.js';
import {
  IncidentWorkflowRequest,
  IncidentWorkflowResult,
} from '../types/agents.js';
import { SentinelAgent } from './sentinel.js';
import { ContainmentAgent } from './containment.js';
import { ForensicsAgent } from './forensics.js';

export interface AgentCoordinatorOptions {
  auditService?: AuditService;
  sentinel?: SentinelAgent;
  containment?: ContainmentAgent;
  forensics?: ForensicsAgent;
}

export class AgentCoordinator {
  private sentinel: SentinelAgent;
  private containment: ContainmentAgent;
  private forensics: ForensicsAgent;
  private auditService?: AuditService;

  constructor(options: AgentCoordinatorOptions = {}) {
    this.auditService = options.auditService;
    this.sentinel = options.sentinel || new SentinelAgent();
    this.containment =
      options.containment || new ContainmentAgent({ auditService: this.auditService });
    this.forensics =
      options.forensics || new ForensicsAgent({ auditService: this.auditService });
  }

  public getSentinel(): SentinelAgent {
    return this.sentinel;
  }

  public getContainment(): ContainmentAgent {
    return this.containment;
  }

  public getForensics(): ForensicsAgent {
    return this.forensics;
  }

  /**
   * Executes autonomous incident response workflow:
   * Sentinel Triage -> Containment (if warranted) -> Forensics RCA
   */
  public async processAlert(request: IncidentWorkflowRequest): Promise<IncidentWorkflowResult> {
    const { alert, autoContain = true } = request;

    // 1. Sentinel Triage
    const triage = this.sentinel.triageAlert(alert);

    let containmentResult;
    let newStatus = alert.status;

    // 2. Automated Containment (if warranted by decision or critical severity)
    if (triage.decision === 'CONTAIN' || (autoContain && alert.severity === 'CRITICAL')) {
      containmentResult = this.containment.quarantine({
        targetType: 'ACTOR',
        targetId: alert.actorId || alert.affectedResource,
        reason: `Automated containment triggered by Sentinel triage: ${triage.rationale}`,
        initiatedBy: 'agent-coordinator',
      });
      newStatus = 'CONTAINED';
    } else if (triage.decision === 'INVESTIGATE') {
      newStatus = 'INVESTIGATING';
    } else if (triage.decision === 'SUPPRESS') {
      newStatus = 'RESOLVED';
    }

    // 3. Forensics RCA Synthesis
    const rcaReport = this.forensics.generateRCAReport(alert);

    // 4. Record Coordination Audit
    if (this.auditService) {
      this.auditService.append({
        who: 'autonomous-agent-coordinator',
        what: `incident.coordinated_response:${alert.alertId}`,
        where: 'sovereign-agent-mesh',
        why: `Executed autonomous response pipeline for alert '${alert.title}'`,
        result: 'SUCCESS',
        details: {
          alertId: alert.alertId,
          triageDecision: triage.decision,
          contained: !!containmentResult,
          quarantineId: containmentResult?.quarantineRecord.quarantineId,
          reportId: rcaReport.reportId,
        },
      });
    }

    return {
      alertId: alert.alertId,
      status: newStatus,
      triage,
      containment: containmentResult,
      rcaReport,
    };
  }
}
