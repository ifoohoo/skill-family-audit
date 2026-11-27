// @feature FND-FR-039
// @decision FND-ADR-040
// @design FND-DES-049

/** 会话追溯包的公共 Schema $id。 */
export const SESSION_TRACE_BUNDLE_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/session-trace-bundle.json";

/** 会话追溯包的文档类型标识。 */
export const SESSION_TRACE_BUNDLE_KIND = "skill-family.session-trace-bundle";

export function stbInvariantFailure(message, instancePath, params = {}) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [
      {
        keyword: "sessionTraceBundle",
        instancePath,
        schemaPath: `${SESSION_TRACE_BUNDLE_SCHEMA_ID}#invariants`,
        message,
        params,
      },
    ],
    data: undefined,
  };
}

/**
 * 校验结构通过后的会话追溯包引用完整性与全部 8 项可观测性诚实不变量（零外部依赖纯函数）。
 */
export function verifySessionTraceBundleInvariants(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return stbInvariantFailure("会话追溯包必须是 JSON 对象", "");
  }
  if (
    !Array.isArray(data.evidenceRefs) ||
    !Array.isArray(data.rawSources) ||
    !Array.isArray(data.sessions) ||
    !Array.isArray(data.interactions) ||
    !Array.isArray(data.skillActivations) ||
    !Array.isArray(data.methodLocks) ||
    !Array.isArray(data.hitlDecisions) ||
    !Array.isArray(data.toolCalls) ||
    !Array.isArray(data.sandboxEvents) ||
    !Array.isArray(data.claims) ||
    !data.seal ||
    typeof data.seal !== "object" ||
    !data.attempt ||
    typeof data.attempt !== "object" ||
    !data.producer ||
    typeof data.producer !== "object"
  ) {
    return stbInvariantFailure("会话追溯包缺少必需顶层集合或封存对象", "");
  }

  const evidenceIds = new Set();
  for (let i = 0; i < data.evidenceRefs.length; i += 1) {
    const ref = data.evidenceRefs[i];
    if (!ref || typeof ref.evidenceId !== "string") {
      return stbInvariantFailure("evidenceRefs 条目非法", `/evidenceRefs/${i}`);
    }
    if (evidenceIds.has(ref.evidenceId)) {
      return stbInvariantFailure(`重复的 evidenceId "${ref.evidenceId}"`, `/evidenceRefs/${i}/evidenceId`, {
        evidenceId: ref.evidenceId,
      });
    }
    evidenceIds.add(ref.evidenceId);
  }

  const sourceMap = new Map();
  for (let i = 0; i < data.rawSources.length; i += 1) {
    const src = data.rawSources[i];
    if (!src || typeof src.sourceId !== "string" || !src.coverage) {
      return stbInvariantFailure("rawSources 条目非法", `/rawSources/${i}`);
    }
    if (sourceMap.has(src.sourceId)) {
      return stbInvariantFailure(`重复的 sourceId "${src.sourceId}"`, `/rawSources/${i}/sourceId`, {
        sourceId: src.sourceId,
      });
    }
    if (!evidenceIds.has(src.evidenceId)) {
      return stbInvariantFailure(
        `rawSources[${i}] 引用的 evidenceId "${src.evidenceId}" 未在 evidenceRefs 中声明`,
        `/rawSources/${i}/evidenceId`,
        { evidenceId: src.evidenceId },
      );
    }
    const cov = src.coverage;
    if (cov.readBytes > cov.totalBytes) {
      return stbInvariantFailure(
        `rawSources[${i}] 的 readBytes 不能大于 totalBytes`,
        `/rawSources/${i}/coverage/readBytes`,
      );
    }
    if (cov.keptLines > cov.totalLines) {
      return stbInvariantFailure(
        `rawSources[${i}] 的 keptLines 不能大于 totalLines`,
        `/rawSources/${i}/coverage/keptLines`,
      );
    }
    if (Array.isArray(cov.droppedRanges)) {
      for (let r = 0; r < cov.droppedRanges.length; r += 1) {
        const rng = cov.droppedRanges[r];
        if (rng && typeof rng.startByte === "number" && typeof rng.endByte === "number" && rng.startByte > rng.endByte) {
          return stbInvariantFailure(
            `rawSources[${i}].droppedRanges[${r}] 的 startByte 不能大于 endByte`,
            `/rawSources/${i}/coverage/droppedRanges/${r}`,
          );
        }
      }
    }
    if (cov.complete) {
      if (
        cov.readBytes !== cov.totalBytes ||
        cov.keptLines !== cov.totalLines ||
        (Array.isArray(cov.droppedRanges) && cov.droppedRanges.length > 0)
      ) {
        return stbInvariantFailure(
          `rawSources[${i}] 声明 complete=true 时 readBytes/keptLines 必须等于总量且 droppedRanges 为空`,
          `/rawSources/${i}/coverage/complete`,
        );
      }
    }
    sourceMap.set(src.sourceId, src);
  }

  const checkRawLocator = (locator, pathPrefix) => {
    if (!locator) return null;
    const src = sourceMap.get(locator.sourceId);
    if (!src) {
      return stbInvariantFailure(
        `rawLocator 引用的 sourceId "${locator.sourceId}" 未在 rawSources 中声明`,
        `${pathPrefix}/sourceId`,
        { sourceId: locator.sourceId },
      );
    }
    if (locator.byteOffset + locator.byteLength > src.coverage.totalBytes) {
      return stbInvariantFailure(
        `rawLocator 字节区间 [${locator.byteOffset}, ${locator.byteOffset + locator.byteLength}) 超出数据源 "${locator.sourceId}" 总字节数 ${src.coverage.totalBytes}`,
        `${pathPrefix}/byteLength`,
      );
    }
    return null;
  };

  const sessionMap = new Map();
  let rootCount = 0;
  for (let i = 0; i < data.sessions.length; i += 1) {
    const s = data.sessions[i];
    if (!s || typeof s.sessionId !== "string") {
      return stbInvariantFailure("sessions 条目非法", `/sessions/${i}`);
    }
    if (sessionMap.has(s.sessionId)) {
      return stbInvariantFailure(`重复的 sessionId "${s.sessionId}"`, `/sessions/${i}/sessionId`, {
        sessionId: s.sessionId,
      });
    }
    sessionMap.set(s.sessionId, s);
    if (s.parentSessionId === null) rootCount += 1;

    if (
      (data.producer.captureMode === "offline_transcript" || s.host?.boundary === "transcript_replay") &&
      s.observability?.tier === "T0_live_acp"
    ) {
      return stbInvariantFailure(
        `离线日志回放会话 "${s.sessionId}" 不能声明可观测等级 T0_live_acp`,
        `/sessions/${i}/observability/tier`,
        { sessionId: s.sessionId },
      );
    }

    const obs = s.observability?.fields || {};
    if (obs.osProcess === "absent" && s.osProcess !== null && s.osProcess !== undefined) {
      return stbInvariantFailure(
        `会话 "${s.sessionId}" 声明 osProcess=absent 时 osProcess 字段必须为 null`,
        `/sessions/${i}/osProcess`,
      );
    }
    if ((obs.exposedTools === "absent" || s.exposedToolsSource === "absent") && s.exposedTools !== null) {
      return stbInvariantFailure(
        `会话 "${s.sessionId}" 声明 exposedTools 缺失时 exposedTools 字段必须为 null`,
        `/sessions/${i}/exposedTools`,
      );
    }
    if (obs.writeObservation === "absent") {
      if (
        s.writeScope?.observation?.method !== "absent" ||
        s.writeScope?.observation?.baselineTreeSha256 !== null ||
        s.writeScope?.observation?.finalTreeSha256 !== null ||
        s.writeScope?.observedWrites !== null
      ) {
        return stbInvariantFailure(
          `会话 "${s.sessionId}" 声明 writeObservation=absent 时写观测字段必须为 absent/null`,
          `/sessions/${i}/writeScope`,
        );
      }
    }

    for (let t = 0; t < (s.turns || []).length; t += 1) {
      const turn = s.turns[t];
      if (obs.perTurnUsage === "absent") {
        if (
          turn.inputTokens !== null ||
          turn.cacheReadTokens !== null ||
          turn.cacheWriteTokens !== null ||
          turn.outputTokens !== null ||
          turn.occupancyTokens !== null ||
          turn.windowRatioBp !== null ||
          turn.measurementSource !== "unavailable"
        ) {
          return stbInvariantFailure(
            `会话 "${s.sessionId}" 声明 perTurnUsage=absent 时第 ${t} 轮计量字段必须为 null 且来源为 unavailable（禁止补 0）`,
            `/sessions/${i}/turns/${t}`,
          );
        }
      }
      const locErr = checkRawLocator(turn.rawLocator, `/sessions/${i}/turns/${t}/rawLocator`);
      if (locErr) return locErr;
    }
  }

  const rootNode = sessionMap.get(data.rootSessionId);
  if (!rootNode || rootNode.parentSessionId !== null || rootCount !== 1) {
    return stbInvariantFailure(
      `rootSessionId "${data.rootSessionId}" 必须指向唯一 parentSessionId === null 的根会话`,
      "/rootSessionId",
      { rootSessionId: data.rootSessionId, rootCount },
    );
  }

  for (let i = 0; i < data.sessions.length; i += 1) {
    const s = data.sessions[i];
    if (s.parentSessionId !== null && !sessionMap.has(s.parentSessionId)) {
      return stbInvariantFailure(
        `会话 "${s.sessionId}" 的 parentSessionId "${s.parentSessionId}" 不存在`,
        `/sessions/${i}/parentSessionId`,
      );
    }
    if (s.contextLineage?.forkedFromSessionId && !sessionMap.has(s.contextLineage.forkedFromSessionId)) {
      return stbInvariantFailure(
        `会话 "${s.sessionId}" 的 forkedFromSessionId "${s.contextLineage.forkedFromSessionId}" 不存在`,
        `/sessions/${i}/contextLineage/forkedFromSessionId`,
      );
    }
    const visited = new Set([s.sessionId]);
    let cur = s.parentSessionId ? sessionMap.get(s.parentSessionId) : null;
    while (cur) {
      if (visited.has(cur.sessionId)) {
        return stbInvariantFailure(`会话父子链存在环路 "${cur.sessionId}"`, `/sessions/${i}/parentSessionId`);
      }
      visited.add(cur.sessionId);
      cur = cur.parentSessionId ? sessionMap.get(cur.parentSessionId) : null;
    }
  }

  const interactionIds = new Set();
  for (let i = 0; i < data.interactions.length; i += 1) {
    const it = data.interactions[i];
    if (interactionIds.has(it.interactionId)) {
      return stbInvariantFailure(`重复的 interactionId "${it.interactionId}"`, `/interactions/${i}/interactionId`);
    }
    interactionIds.add(it.interactionId);
    if (!sessionMap.has(it.fromSessionId) || !sessionMap.has(it.toSessionId)) {
      return stbInvariantFailure(`interactions[${i}] 引用了不存在的会话标识`, `/interactions/${i}`);
    }
    if (it.payload?.evidenceId && !evidenceIds.has(it.payload.evidenceId)) {
      return stbInvariantFailure(`interactions[${i}] 引用了未登记的 evidenceId`, `/interactions/${i}/payload/evidenceId`);
    }
  }

  for (let i = 0; i < data.skillActivations.length; i += 1) {
    const sa = data.skillActivations[i];
    if (!sessionMap.has(sa.sessionId)) {
      return stbInvariantFailure(`skillActivations[${i}] 引用了不存在的 sessionId`, `/skillActivations/${i}/sessionId`);
    }
  }

  for (let i = 0; i < data.methodLocks.length; i += 1) {
    const ml = data.methodLocks[i];
    if (!sessionMap.has(ml.sessionId)) {
      return stbInvariantFailure(`methodLocks[${i}] 引用了不存在的 sessionId`, `/methodLocks/${i}/sessionId`);
    }
    if (ml.bypass?.evidenceId && !evidenceIds.has(ml.bypass.evidenceId)) {
      return stbInvariantFailure(`methodLocks[${i}].bypass 引用了未登记的 evidenceId`, `/methodLocks/${i}/bypass/evidenceId`);
    }
  }

  const decisionIds = new Set();
  for (let i = 0; i < data.hitlDecisions.length; i += 1) {
    const d = data.hitlDecisions[i];
    if (decisionIds.has(d.decisionId)) {
      return stbInvariantFailure(`重复的 decisionId "${d.decisionId}"`, `/hitlDecisions/${i}/decisionId`);
    }
    decisionIds.add(d.decisionId);
    if (!sessionMap.has(d.sessionId)) {
      return stbInvariantFailure(`hitlDecisions[${i}] 引用了不存在的 sessionId`, `/hitlDecisions/${i}/sessionId`);
    }
    const locErr = checkRawLocator(d.rawLocator, `/hitlDecisions/${i}/rawLocator`);
    if (locErr) return locErr;
  }

  const callIds = new Set();
  for (let i = 0; i < data.toolCalls.length; i += 1) {
    const tc = data.toolCalls[i];
    if (callIds.has(tc.callId)) {
      return stbInvariantFailure(`重复的 callId "${tc.callId}"`, `/toolCalls/${i}/callId`);
    }
    callIds.add(tc.callId);
  }

  for (let i = 0; i < data.toolCalls.length; i += 1) {
    const tc = data.toolCalls[i];
    const owner = sessionMap.get(tc.sessionId);
    if (!owner) {
      return stbInvariantFailure(`toolCalls[${i}] 引用了不存在的 sessionId`, `/toolCalls/${i}/sessionId`);
    }
    const obsFields = owner.observability?.fields || {};
    if (obsFields.toolArgs === "absent") {
      if (tc.argsSha256 !== null || tc.sanitizedCommandOrTarget !== null) {
        return stbInvariantFailure(
          `toolCalls[${i}] 所属会话声明 toolArgs=absent 时 argsSha256 与 sanitizedCommandOrTarget 必须为 null`,
          `/toolCalls/${i}`,
        );
      }
    } else if (tc.argsSha256 === null || tc.sanitizedCommandOrTarget === null) {
      return stbInvariantFailure(
        `toolCalls[${i}] 未声明 toolArgs=absent 时 argsSha256 与 sanitizedCommandOrTarget 不能为空`,
        `/toolCalls/${i}`,
      );
    }
    if (obsFields.toolOutput === "absent") {
      if (tc.outputByteLength !== null || tc.outputTruncated !== null || tc.outputSha256 !== null) {
        return stbInvariantFailure(
          `toolCalls[${i}] 所属会话声明 toolOutput=absent 时输出统计与摘要字段必须为 null`,
          `/toolCalls/${i}`,
        );
      }
    }
    if ((obsFields.exitCode === "absent" || tc.exitCodeSource === "absent") && tc.exitCode !== null) {
      return stbInvariantFailure(
        `toolCalls[${i}] 声明 exitCode 缺失时 exitCode 字段必须为 null`,
        `/toolCalls/${i}/exitCode`,
      );
    }
    if (tc.spawnedSessionId && !sessionMap.has(tc.spawnedSessionId)) {
      return stbInvariantFailure(
        `toolCalls[${i}] 引用的 spawnedSessionId "${tc.spawnedSessionId}" 不存在`,
        `/toolCalls/${i}/spawnedSessionId`,
      );
    }
    if (tc.parentCallId && !callIds.has(tc.parentCallId)) {
      return stbInvariantFailure(
        `toolCalls[${i}] 引用的 parentCallId "${tc.parentCallId}" 不存在`,
        `/toolCalls/${i}/parentCallId`,
      );
    }
    if (tc.authorizedByDecisionId && !decisionIds.has(tc.authorizedByDecisionId)) {
      return stbInvariantFailure(
        `toolCalls[${i}] 引用的 authorizedByDecisionId 未在 hitlDecisions 中声明`,
        `/toolCalls/${i}/authorizedByDecisionId`,
      );
    }
    if (tc.evidenceId && !evidenceIds.has(tc.evidenceId)) {
      return stbInvariantFailure(`toolCalls[${i}] 引用了未登记的 evidenceId`, `/toolCalls/${i}/evidenceId`);
    }
    const locErr = checkRawLocator(tc.rawLocator, `/toolCalls/${i}/rawLocator`);
    if (locErr) return locErr;
  }

  for (let i = 0; i < data.sessions.length; i += 1) {
    const s = data.sessions[i];
    const writes = s.writeScope?.observedWrites;
    if (Array.isArray(writes)) {
      for (let w = 0; w < writes.length; w += 1) {
        if (writes[w]?.callId && !callIds.has(writes[w].callId)) {
          return stbInvariantFailure(
            `sessions[${i}].writeScope.observedWrites[${w}] 引用的 callId "${writes[w].callId}" 不存在`,
            `/sessions/${i}/writeScope/observedWrites/${w}/callId`,
          );
        }
      }
    }
  }

  const eventIds = new Set();
  for (let i = 0; i < data.sandboxEvents.length; i += 1) {
    const se = data.sandboxEvents[i];
    if (eventIds.has(se.eventId)) {
      return stbInvariantFailure(`重复的 eventId "${se.eventId}"`, `/sandboxEvents/${i}/eventId`);
    }
    eventIds.add(se.eventId);
    const owner = sessionMap.get(se.sessionId);
    if (!owner) {
      return stbInvariantFailure(`sandboxEvents[${i}] 引用了不存在的 sessionId`, `/sandboxEvents/${i}/sessionId`);
    }
    if (owner.observability?.fields?.sandboxEvents === "absent") {
      return stbInvariantFailure(
        `会话 "${se.sessionId}" 声明 sandboxEvents=absent 时不能存在属于该会话的 sandboxEvents 记录`,
        `/sandboxEvents/${i}/sessionId`,
      );
    }
    if (se.callId && !callIds.has(se.callId)) {
      return stbInvariantFailure(`sandboxEvents[${i}] 引用了不存在的 callId`, `/sandboxEvents/${i}/callId`);
    }
    const locErr = checkRawLocator(se.rawLocator, `/sandboxEvents/${i}/rawLocator`);
    if (locErr) return locErr;
  }

  const claimIds = new Set();
  for (let i = 0; i < data.claims.length; i += 1) {
    const claim = data.claims[i];
    if (claimIds.has(claim.claimId)) {
      return stbInvariantFailure(`重复的 claimId "${claim.claimId}"`, `/claims/${i}/claimId`);
    }
    claimIds.add(claim.claimId);
    if (!sessionMap.has(claim.sessionId)) {
      return stbInvariantFailure(`claims[${i}] 引用了不存在的 sessionId`, `/claims/${i}/sessionId`);
    }
    for (let c = 0; c < (claim.agentCitedCallIds || []).length; c += 1) {
      if (!callIds.has(claim.agentCitedCallIds[c])) {
        return stbInvariantFailure(
          `claims[${i}].agentCitedCallIds[${c}] 引用了不存在的 callId "${claim.agentCitedCallIds[c]}"`,
          `/claims/${i}/agentCitedCallIds/${c}`,
        );
      }
    }
    for (let e = 0; e < (claim.agentCitedEvidenceIds || []).length; e += 1) {
      if (!evidenceIds.has(claim.agentCitedEvidenceIds[e])) {
        return stbInvariantFailure(
          `claims[${i}].agentCitedEvidenceIds[${e}] 引用了未登记的 evidenceId "${claim.agentCitedEvidenceIds[e]}"`,
          `/claims/${i}/agentCitedEvidenceIds/${e}`,
        );
      }
    }
    const locErr = checkRawLocator(claim.rawLocator, `/claims/${i}/rawLocator`);
    if (locErr) return locErr;
  }

  if (data.seal.attemptId !== data.attempt.attemptId) {
    return stbInvariantFailure("seal.attemptId 必须与 attempt.attemptId 一致", "/seal/attemptId");
  }
  const ext = data.seal.externalBinding;
  if (ext?.status === "bound") {
    if (!ext.kind || !ext.recordDigest) {
      return stbInvariantFailure(
        "seal.externalBinding.status=bound 时必须同时提供 kind 与 recordDigest",
        "/seal/externalBinding",
      );
    }
  } else if (ext?.status === "pending") {
    if (ext.kind !== null || ext.recordDigest !== null) {
      return stbInvariantFailure(
        "seal.externalBinding.status=pending 时 kind 与 recordDigest 必须为 null",
        "/seal/externalBinding",
      );
    }
  }

  return { valid: true, errorCode: null, errors: [], data };
}
