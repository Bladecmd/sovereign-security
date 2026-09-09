/**
 * Sovereign Security — Foundation V0.1
 * Machine-Readable AI Agent Tool Permission Registry & Evaluator
 */

import { AgentToolPolicy, ToolPermissionCheck } from '../types/ai-security.js';

export class AgentToolPermissionRegistry {
  private policies: Map<string, AgentToolPolicy> = new Map();

  constructor() {
    this.registerDefaultAgentPolicies();
  }

  /**
   * Register or update an agent tool policy
   */
  public registerPolicy(policy: AgentToolPolicy): void {
    this.policies.set(policy.agentId.toLowerCase(), policy);
  }

  /**
   * Retrieve an agent tool policy
   */
  public getPolicy(agentId: string): AgentToolPolicy | undefined {
    return this.policies.get(agentId.toLowerCase());
  }

  /**
   * Check whether an agent has permission to execute a specific tool with parameters
   */
  public checkPermission(
    agentId: string,
    toolName: string,
    parameters: Record<string, unknown> = {}
  ): ToolPermissionCheck {
    const policy = this.getPolicy(agentId);

    // If agent has no policy defined, deny by default (Zero-Trust)
    if (!policy) {
      return {
        agentId,
        toolName,
        parameters,
        decision: 'DENY',
        reason: `No tool policy registered for agent '${agentId}'. Access denied by default.`,
      };
    }

    // 1. Check explicit denied tools
    if (policy.deniedTools.includes(toolName)) {
      return {
        agentId,
        toolName,
        parameters,
        decision: 'DENY',
        reason: `Agent '${policy.agentName}' is explicitly prohibited from invoking tool '${toolName}'.`,
      };
    }

    // 2. Check approval-required tools
    if (policy.approvalRequiredTools.includes(toolName)) {
      return {
        agentId,
        toolName,
        parameters,
        decision: 'REQUIRE_APPROVAL',
        reason: `Tool '${toolName}' invoked by agent '${policy.agentName}' requires human executive approval before execution.`,
      };
    }

    // 3. Check explicit allowed tools
    if (policy.allowedTools.includes(toolName)) {
      // Check parameter constraints if any exist
      const constraint = policy.parameterConstraints?.[toolName];
      if (constraint && !constraint(parameters)) {
        return {
          agentId,
          toolName,
          parameters,
          decision: 'DENY',
          reason: `Tool '${toolName}' invocation failed parameter constraint validation for agent '${policy.agentName}'.`,
        };
      }

      return {
        agentId,
        toolName,
        parameters,
        decision: 'ALLOW',
        reason: `Tool '${toolName}' is authorized for agent '${policy.agentName}'.`,
      };
    }

    // 4. Default policy action
    return {
      agentId,
      toolName,
      parameters,
      decision: policy.defaultAction,
      reason: `Tool '${toolName}' not explicitly listed. Applying default action '${policy.defaultAction}' for agent '${policy.agentName}'.`,
    };
  }

  /**
   * Register default policies including VEGA
   */
  private registerDefaultAgentPolicies(): void {
    // VEGA Agent Policy: Executive intelligence and business analyst
    const vegaPolicy: AgentToolPolicy = {
      agentId: 'vega',
      agentName: 'VEGA (Executive Intelligence)',
      description: 'Sovereign OS Executive Intelligence Agent for business telemetry and strategic analysis',
      defaultAction: 'DENY',
      allowedTools: [
        'read_business_telemetry',
        'analyse_data',
        'draft_recommendation',
        'query_metric_dashboard',
        'summarize_reports',
      ],
      deniedTools: [
        'transfer_funds',
        'delete_production_data',
        'deploy_destructive_infrastructure',
        'export_credentials',
        'modify_iam_roles',
      ],
      approvalRequiredTools: [
        'send_executive_alert',
        'trigger_sync_workflow',
        'stage_deployment_manifest',
      ],
      parameterConstraints: {
        read_business_telemetry: (params) => {
          // Prevent requesting telemetry from unauthorized namespaces
          const ns = params.namespace as string | undefined;
          return !ns || !ns.startsWith('classified_');
        },
      },
    };

    this.registerPolicy(vegaPolicy);
  }
}
