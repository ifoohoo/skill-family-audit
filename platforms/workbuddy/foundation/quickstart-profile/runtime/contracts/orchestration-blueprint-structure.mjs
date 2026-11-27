// @feature FND-FR-039
// @decision FND-ADR-040
// @design FND-DES-049

/** 多会话编排蓝图的公共 Schema $id。 */
export const ORCHESTRATION_BLUEPRINT_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/orchestration-blueprint.json";

/** 多会话编排蓝图的文档类型标识。 */
export const ORCHESTRATION_BLUEPRINT_KIND = "skill-family.orchestration-blueprint";

const SIDE_EFFECT_RANK = Object.freeze({
  read_only: 0,
  workspace_write: 1,
  external_side_effect: 2,
});

export function blueprintStructureFailure(message, instancePath, params = {}) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [
      {
        keyword: "orchestrationBlueprint",
        instancePath,
        schemaPath: `${ORCHESTRATION_BLUEPRINT_SCHEMA_ID}#structure`,
        message,
        params,
      },
    ],
    data: undefined,
  };
}

/**
 * 校验多会话编排蓝图的图结构与引用完整性（零外部依赖纯函数，迭代拓扑判环，不越界承担下游审计语义规则）。
 */
export function verifyOrchestrationBlueprintStructure(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return blueprintStructureFailure("编排蓝图必须是 JSON 对象", "");
  }
  if (
    !Array.isArray(data.toolContracts) ||
    !Array.isArray(data.nodes) ||
    !Array.isArray(data.edges) ||
    !Array.isArray(data.hitlGates) ||
    !Array.isArray(data.expectedEvidence) ||
    !Array.isArray(data.terminalNodeIds)
  ) {
    return blueprintStructureFailure("编排蓝图缺少必需顶层集合", "");
  }

  const toolMap = new Map();
  for (let i = 0; i < data.toolContracts.length; i += 1) {
    const t = data.toolContracts[i];
    if (!t || typeof t.toolId !== "string") {
      return blueprintStructureFailure("toolContracts 条目非法", `/toolContracts/${i}`);
    }
    if (toolMap.has(t.toolId)) {
      return blueprintStructureFailure(`重复的 toolId "${t.toolId}"`, `/toolContracts/${i}/toolId`);
    }
    toolMap.set(t.toolId, t);
  }

  const nodeMap = new Map();
  for (let i = 0; i < data.nodes.length; i += 1) {
    const n = data.nodes[i];
    if (!n || typeof n.nodeId !== "string") {
      return blueprintStructureFailure("nodes 条目非法", `/nodes/${i}`);
    }
    if (nodeMap.has(n.nodeId)) {
      return blueprintStructureFailure(`重复的 nodeId "${n.nodeId}"`, `/nodes/${i}/nodeId`);
    }
    const isDetScript = n.executor === "deterministic_script";
    const isNoLlm = n.modelTier === "deterministic_no_llm";
    if (isDetScript !== isNoLlm) {
      return blueprintStructureFailure(
        `节点 "${n.nodeId}" 的 deterministic_script 与 modelTier=deterministic_no_llm 必须双向等价`,
        `/nodes/${i}/modelTier`,
      );
    }
    const ceilingRank = SIDE_EFFECT_RANK[n.sideEffectCeiling];
    for (let k = 0; k < (n.allowedTools || []).length; k += 1) {
      const tid = n.allowedTools[k];
      const tool = toolMap.get(tid);
      if (!tool) {
        return blueprintStructureFailure(
          `节点 "${n.nodeId}" 引用的工具 "${tid}" 未在 toolContracts 中声明`,
          `/nodes/${i}/allowedTools/${k}`,
        );
      }
      if (SIDE_EFFECT_RANK[tool.sideEffectClass] > ceilingRank) {
        return blueprintStructureFailure(
          `节点 "${n.nodeId}" 允许的工具 "${tid}" 副作用等级超出节点上限 "${n.sideEffectCeiling}"`,
          `/nodes/${i}/allowedTools/${k}`,
        );
      }
    }
    nodeMap.set(n.nodeId, n);
  }

  if (!nodeMap.has(data.entryNodeId)) {
    return blueprintStructureFailure(`entryNodeId "${data.entryNodeId}" 不存在于 nodes 中`, "/entryNodeId");
  }
  for (let i = 0; i < data.terminalNodeIds.length; i += 1) {
    if (!nodeMap.has(data.terminalNodeIds[i])) {
      return blueprintStructureFailure(
        `terminalNodeIds[${i}] "${data.terminalNodeIds[i]}" 不存在于 nodes 中`,
        `/terminalNodeIds/${i}`,
      );
    }
  }

  const evidenceMap = new Map();
  for (let i = 0; i < data.expectedEvidence.length; i += 1) {
    const ev = data.expectedEvidence[i];
    if (evidenceMap.has(ev.evidenceKey)) {
      return blueprintStructureFailure(`重复的 evidenceKey "${ev.evidenceKey}"`, `/expectedEvidence/${i}/evidenceKey`);
    }
    if (!nodeMap.has(ev.producedBy)) {
      return blueprintStructureFailure(
        `expectedEvidence[${i}] 的 producedBy "${ev.producedBy}" 不存在于 nodes 中`,
        `/expectedEvidence/${i}/producedBy`,
      );
    }
    evidenceMap.set(ev.evidenceKey, ev);
  }

  for (let i = 0; i < data.nodes.length; i += 1) {
    const n = data.nodes[i];
    if (n.fanOut) {
      if (n.fanOut.maxBranches < n.fanOut.minBranches) {
        return blueprintStructureFailure(`节点 "${n.nodeId}" 的 fanOut.maxBranches 不能小于 minBranches`, `/nodes/${i}/fanOut`);
      }
      if (!nodeMap.has(n.fanOut.joinNodeId)) {
        return blueprintStructureFailure(
          `节点 "${n.nodeId}" 的 fanOut.joinNodeId "${n.fanOut.joinNodeId}" 不存在于 nodes 中`,
          `/nodes/${i}/fanOut/joinNodeId`,
        );
      }
    }
    if (n.independence && Array.isArray(n.independence.reviewsNodes)) {
      for (let r = 0; r < n.independence.reviewsNodes.length; r += 1) {
        const targetId = n.independence.reviewsNodes[r];
        if (!nodeMap.has(targetId)) {
          return blueprintStructureFailure(
            `节点 "${n.nodeId}" 的 reviewsNodes[${r}] "${targetId}" 不存在于 nodes 中`,
            `/nodes/${i}/independence/reviewsNodes/${r}`,
          );
        }
      }
    }
    if (n.onFailure?.route && typeof n.onFailure.route === "string" && n.onFailure.action === "route_to_node") {
      if (!nodeMap.has(n.onFailure.route)) {
        return blueprintStructureFailure(
          `节点 "${n.nodeId}" 的 onFailure.route "${n.onFailure.route}" 不存在于 nodes 中`,
          `/nodes/${i}/onFailure/route`,
        );
      }
    }
    if (n.hostFallbackPolicy?.variantNodeId && !nodeMap.has(n.hostFallbackPolicy.variantNodeId)) {
      return blueprintStructureFailure(
        `节点 "${n.nodeId}" 的 variantNodeId "${n.hostFallbackPolicy.variantNodeId}" 不存在于 nodes 中`,
        `/nodes/${i}/hostFallbackPolicy/variantNodeId`,
      );
    }
    for (let c = 0; c < (n.completionCriteria || []).length; c += 1) {
      const ek = n.completionCriteria[c].evidenceKey;
      if (!evidenceMap.has(ek)) {
        return blueprintStructureFailure(
          `节点 "${n.nodeId}" 的 completionCriteria 引用了未声明的 evidenceKey "${ek}"`,
          `/nodes/${i}/completionCriteria/${c}/evidenceKey`,
        );
      }
    }
  }

  const edgeMap = new Map();
  const forwardAdj = new Map([...nodeMap.keys()].map((id) => [id, []]));
  const inDegree = new Map([...nodeMap.keys()].map((id) => [id, 0]));
  const reworkEdges = [];

  for (let i = 0; i < data.edges.length; i += 1) {
    const e = data.edges[i];
    if (edgeMap.has(e.edgeId)) {
      return blueprintStructureFailure(`重复的 edgeId "${e.edgeId}"`, `/edges/${i}/edgeId`);
    }
    if (!nodeMap.has(e.fromNodeId) || !nodeMap.has(e.toNodeId)) {
      return blueprintStructureFailure(`边 "${e.edgeId}" 的端点必须存在于 nodes 中`, `/edges/${i}`);
    }
    for (const reqEv of e.handoff?.requiredUpstreamEvidence || []) {
      if (!evidenceMap.has(reqEv)) {
        return blueprintStructureFailure(
          `边 "${e.edgeId}" 引用了未声明的 requiredUpstreamEvidence "${reqEv}"`,
          `/edges/${i}/handoff/requiredUpstreamEvidence`,
        );
      }
    }
    if (e.edgeKind === "rework_feedback") {
      if (!e.rework || typeof e.rework.maxIterations !== "number") {
        return blueprintStructureFailure(
          `返工边 "${e.edgeId}" 必须提供 rework.maxIterations`,
          `/edges/${i}/rework`,
        );
      }
      reworkEdges.push({ edge: e, index: i });
    } else {
      if (e.rework !== null && e.rework !== undefined) {
        return blueprintStructureFailure(
          `非返工边 "${e.edgeId}" 不得携带 rework 配置块`,
          `/edges/${i}/rework`,
        );
      }
      forwardAdj.get(e.fromNodeId).push(e.toNodeId);
      inDegree.set(e.toNodeId, (inDegree.get(e.toNodeId) || 0) + 1);
    }
    edgeMap.set(e.edgeId, e);
  }

  const gateMap = new Map();
  for (let i = 0; i < data.hitlGates.length; i += 1) {
    const g = data.hitlGates[i];
    if (gateMap.has(g.gateId)) {
      return blueprintStructureFailure(`重复的 gateId "${g.gateId}"`, `/hitlGates/${i}/gateId`);
    }
    gateMap.set(g.gateId, g);
    if (g.placement === "on_edge") {
      if (!g.edgeId || !edgeMap.has(g.edgeId)) {
        return blueprintStructureFailure(`门禁 "${g.gateId}" placement=on_edge 时必须绑定已存在的 edgeId`, `/hitlGates/${i}/edgeId`);
      }
    } else {
      if (g.edgeId !== null && g.edgeId !== undefined) {
        return blueprintStructureFailure(`门禁 "${g.gateId}" 非 on_edge 时 edgeId 必须为 null`, `/hitlGates/${i}/edgeId`);
      }
      if (!g.attachToNodeId || !nodeMap.has(g.attachToNodeId)) {
        return blueprintStructureFailure(
          `门禁 "${g.gateId}" 必须绑定已存在的 attachToNodeId`,
          `/hitlGates/${i}/attachToNodeId`,
        );
      }
    }
    if (g.onReject?.action === "route_to_node" && g.onReject.route && !nodeMap.has(g.onReject.route)) {
      return blueprintStructureFailure(
        `门禁 "${g.gateId}" 的 onReject.route "${g.onReject.route}" 不存在于 nodes 中`,
        `/hitlGates/${i}/onReject/route`,
      );
    }
  }

  for (const { edge, index } of reworkEdges) {
    if (edge.rework?.onExhausted?.gateId && !gateMap.has(edge.rework.onExhausted.gateId)) {
      return blueprintStructureFailure(
        `返工边 "${edge.edgeId}" 引用的 onExhausted.gateId "${edge.rework.onExhausted.gateId}" 不存在于 hitlGates 中`,
        `/edges/${index}/rework/onExhausted/gateId`,
      );
    }
  }

  // 1. 从 entryNodeId 沿非返工正向边可达全部节点（迭代 BFS）
  const reachable = new Set([data.entryNodeId]);
  const bfsQueue = [data.entryNodeId];
  let head = 0;
  while (head < bfsQueue.length) {
    const cur = bfsQueue[head++];
    for (const nxt of forwardAdj.get(cur) || []) {
      if (!reachable.has(nxt)) {
        reachable.add(nxt);
        bfsQueue.push(nxt);
      }
    }
  }
  for (const nodeId of nodeMap.keys()) {
    if (!reachable.has(nodeId)) {
      return blueprintStructureFailure(`节点 "${nodeId}" 无法从入口 "${data.entryNodeId}" 沿正向边到达`, "/nodes", { nodeId });
    }
  }

  // 2. 剔除 rework_feedback 后的正向图必须无环（迭代 Kahn 算法，支持万级节点零栈溢出）
  const kahnQueue = [];
  for (const [nodeId, deg] of inDegree.entries()) {
    if (deg === 0) kahnQueue.push(nodeId);
  }
  let visitedCount = 0;
  let kHead = 0;
  while (kHead < kahnQueue.length) {
    const u = kahnQueue[kHead++];
    visitedCount += 1;
    for (const v of forwardAdj.get(u) || []) {
      const nextDeg = (inDegree.get(v) || 0) - 1;
      inDegree.set(v, nextDeg);
      if (nextDeg === 0) kahnQueue.push(v);
    }
  }
  if (visitedCount !== nodeMap.size) {
    return blueprintStructureFailure("编排蓝图的非返工正向边存在环路", "/edges");
  }

  // 3. 每条 rework_feedback 边必须指向严格祖先节点（不允许自环 start===goal）
  const canForwardReachStrict = (start, goal) => {
    if (start === goal) return false;
    const seen = new Set([start]);
    const q = [start];
    let qIdx = 0;
    while (qIdx < q.length) {
      const cur = q[qIdx++];
      for (const nxt of forwardAdj.get(cur) || []) {
        if (nxt === goal) return true;
        if (!seen.has(nxt)) {
          seen.add(nxt);
          q.push(nxt);
        }
      }
    }
    return false;
  };
  for (const { edge, index } of reworkEdges) {
    if (!canForwardReachStrict(edge.toNodeId, edge.fromNodeId)) {
      return blueprintStructureFailure(
        `返工边 "${edge.edgeId}" 的目标 "${edge.toNodeId}" 必须是源节点 "${edge.fromNodeId}" 的严格上游祖先节点`,
        `/edges/${index}/toNodeId`,
      );
    }
  }

  return { valid: true, errorCode: null, errors: [], data };
}
