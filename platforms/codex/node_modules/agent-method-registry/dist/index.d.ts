import { D as Diagnostic } from './codes-DJ-T-zoi.js';
export { E as ERROR_CODES, a as ErrorCode } from './codes-DJ-T-zoi.js';

interface SchemaValidationResult {
    valid: boolean;
    diagnostics: Diagnostic[];
    data?: unknown;
}

/** Layer 1: Family API service identity */
interface ServiceIdentity {
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
}
/** Layer 5: Project binding */
interface ProjectBindingData {
    familyId: string;
    apiIdentity: {
        apiId: string;
        apiMajor: number;
        apiRevisionDigest: string;
    };
    implementationIdentity: {
        familyImplementationId: string;
        version: string;
    };
    providerSelector: {
        scope: 'plugin' | 'project';
        pluginId: string;
        projectAuthority?: string;
        host: string;
        canonicalRoot: string;
        packageDigest: string;
        bundleDigest: string;
        provenance: string;
    };
    selectionSource: 'project-binding' | 'unique-compatible' | 'synthetic-migration';
    conformanceEvidence: {
        deterministicAttestation?: string | null;
        behaviorQualification?: string | null;
    };
    authorization?: {
        sideEffectBudget: string;
        granted: boolean;
    };
}
interface ProjectServiceBindingData {
    familyId: string;
    serviceId: string;
    apiIdentity: ProjectBindingData['apiIdentity'];
    implementationIdentity: ProjectBindingData['implementationIdentity'];
    providerSelector: ProjectBindingData['providerSelector'];
    conformanceEvidence: ProjectBindingData['conformanceEvidence'];
    interopTckAttestation: string;
    authorization?: ProjectBindingData['authorization'];
}
/** Layer 6: Run method lock */
interface RunMethodLock {
    documentKind: 'v2-run-lock';
    schemaVersion: 2;
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
    familyImplementationId: string;
    serviceImplementationId: string;
    implementationVersion: string;
    provider: {
        scope: 'plugin' | 'project';
        pluginId: string;
        projectAuthority?: string;
        host: string;
        canonicalRoot: string;
        skillPath: string;
        packageDigest: string;
        provenance: string;
    };
    bundleRoots: string[];
    bundleDigest: string;
    artifactContractRevisionDigest: string;
    sourceDigest: string;
    bindingDigest: string;
    indexDigest: string;
    queryDigest: string;
    projectFactsEvidenceDigest: string;
    conformanceAttestationDigest: string;
    sideEffectSummary: {
        ceiling: string;
        budget: string;
        authorized: boolean;
    };
}
type ApiRecognition = 'STANDARD' | 'THIRD_PARTY' | 'PROJECT';
type Installation = 'INSTALLED' | 'NOT_INSTALLED';
type Enablement = 'ENABLED' | 'NOT_ENABLED';
type Compatibility = 'COMPATIBLE' | 'INCOMPATIBLE' | 'UNKNOWN';
type Trust = 'VERIFIED' | 'UNVERIFIED' | 'REJECTED';
type Resolution = 'NONE' | 'UNIQUE_COMPATIBLE' | 'EXPLICIT_BINDING' | 'AMBIGUOUS';
type SelectionSource = 'unique-compatible' | 'project-binding' | null;
interface ImplementationDescriptor {
    documentKind: 'v2-implementation';
    schemaVersion: 2;
    familyImplementationId: string;
    version: string;
    pluginId: string;
    projectAuthority?: string;
    implements: {
        apiId: string;
        apiMajor: number;
        apiRevisionDigest: string;
    };
    services: Record<string, {
        serviceImplementationId: string;
        skill: string;
    }>;
    bundle: {
        roots: string[];
        treeDigest: string;
    };
    lifecycle: {
        ownership: 'bundled' | 'independent' | 'project-local';
        maturity: 'experimental' | 'incubating' | 'stable' | 'deprecated';
        channel?: 'stable' | 'incubator';
    };
    hostSupport?: Record<string, {
        skillPath?: string;
        available?: boolean;
    }>;
    conformance: {
        deterministicAttestation: string | null;
        behaviorQualification: string | null;
        interopTckAttestations?: string[];
    };
}
interface InventoryEntry {
    pluginId: string;
    projectAuthority?: string;
    canonicalRoot: string;
    version: string;
    packageDigest: string;
    provenance: string;
    host: string;
    snapshotDigest?: string;
    snapshotFreshness?: 'fresh' | 'stale' | 'missing';
}
interface InventoryData {
    documentKind: 'v2-inventory';
    schemaVersion: 2;
    snapshotDigest: string;
    snapshotFreshness: 'fresh' | 'stale' | 'missing';
    entries: InventoryEntry[];
}
interface BindingData {
    documentKind: 'v2-binding';
    schemaVersion: 2;
    bindings: ProjectBindingData[];
    serviceBindings?: ProjectServiceBindingData[];
}
interface ProjectionCandidate {
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
    familyImplementationId: string;
    serviceImplementationId: string;
    version: string;
    provider?: {
        scope: 'plugin' | 'project';
        pluginId: string;
        projectAuthority?: string;
        host: string;
        canonicalRoot: string;
        skillPath: string;
        packageDigest: string;
        bundleDigest: string;
        provenance: string;
    };
    bundleRoots: string[];
    installation: Installation;
    enablement: Enablement;
    compatibility: Compatibility;
    trust: Trust;
    conformanceAttestation: string | null;
    verificationAttestationDigest: string | null;
    authorization?: ProjectBindingData['authorization'];
}
interface ProjectionEntry {
    ref: string;
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
    kind: 'workflow' | 'operation';
    intents: string[];
    summary: string;
    sideEffectCeiling?: string;
    mixSafe: boolean;
    apiRecognition: ApiRecognition;
    installation: Installation;
    enablement: Enablement;
    compatibility: Compatibility;
    trust: Trust;
    resolution: Resolution;
    selectionSource: SelectionSource;
    selectedCandidateId?: string;
    candidates: ProjectionCandidate[];
}
interface ProjectionData {
    documentKind: 'v2-projection';
    schemaVersion: 2;
    inputs: {
        familyApiId: string;
        familyApiMajor: number;
        apiRevisionDigest: string;
        implementationDigest: string;
        inventoryDigest: string;
        bindingDigest: string;
    };
    snapshotDigest: string;
    entries: ProjectionEntry[];
}
interface MethodQuery {
    schemaVersion: 1;
    mode: 'standard';
    candidateServices: Array<{
        serviceId: string;
        apiId: string;
        apiMajor: number;
        apiRevisionDigest: string;
    }>;
    intent: string;
    kind: 'workflow' | 'operation';
    targetArtifact: {
        type: string;
        id: string;
    };
    contractRevisionDigest: string;
    projectFactsEvidenceDigest: string;
    authorization: {
        sideEffectBudget: string;
        granted: boolean;
    };
    registrySnapshot: {
        digest: string;
        freshness: 'fresh' | 'stale' | 'missing';
    };
    queryDigest: string;
}
interface SyntheticIdentity {
    v1Ref: string;
    familyImplementationId: string;
    serviceImplementationId: string;
    syntheticDigest: string;
    provenance: string;
    conversionAlgorithmVersion: string;
}
interface BindingConversion {
    v1Ref: string;
    v2Binding: ProjectBindingData;
    sourceDigest: string;
    conversionAlgorithmVersion: string;
    conversionDigest: string;
}
interface CollisionReport {
    hasCollisions: boolean;
    collisions: Array<{
        ref: string;
        type: 'identity-collision' | 'binding-collision' | 'unsafe-aggregation' | 'unresolved-mapping';
        details: string;
    }>;
}
interface MigrationPlan {
    documentKind: 'v2-migration-plan';
    schemaVersion: 2;
    planDigest: string;
    syntheticIdentities: SyntheticIdentity[];
    bindingConversions: BindingConversion[];
    collisionReport: CollisionReport;
    sourceManifest: Array<{
        path: string;
        digest: string;
    }>;
    targetFiles: Record<string, unknown>;
    snapshot?: {
        snapshotDigest: string;
        timestamp: string;
    };
}

interface PluginProvider {
    scope: 'plugin';
    plugin: string;
    skill: string;
}
interface ProjectProvider {
    scope: 'project';
    skill: string;
}
type Provider = PluginProvider | ProjectProvider;
interface Entry {
    ref: string;
    provider: Provider;
    kind: 'workflow' | 'operation';
    summary: string;
    match: {
        domains: string[];
        artifactTypes: string[];
        intents: string[];
    };
    accepts: string[];
    produces: string[];
    sideEffects: string[];
}
interface CatalogData {
    schemaVersion: number;
    catalog: {
        id: string;
        version: string;
    };
    entries: Entry[];
}
interface ValidateCatalogResult {
    ok: boolean;
    data?: CatalogData | ImplementationDescriptor | InventoryData | RunMethodLock | MigrationPlan;
    diagnostics: Diagnostic[];
}
interface ValidateCatalogDocumentResult<T> {
    ok: boolean;
    data?: T;
    diagnostics: Diagnostic[];
}
type ValidateCatalogV1Result = ValidateCatalogDocumentResult<CatalogData>;
declare function validateCatalog(data: CatalogData): ValidateCatalogV1Result;
declare function validateCatalog(data: ImplementationDescriptor): ValidateCatalogDocumentResult<ImplementationDescriptor>;
declare function validateCatalog(data: InventoryData): ValidateCatalogDocumentResult<InventoryData>;
declare function validateCatalog(data: RunMethodLock): ValidateCatalogDocumentResult<RunMethodLock>;
declare function validateCatalog(data: MigrationPlan): ValidateCatalogDocumentResult<MigrationPlan>;
declare function validateCatalog(data: unknown): ValidateCatalogResult;

interface Override {
    provider: ProjectProvider;
}
interface ProjectEntry {
    ref: string;
    provider: ProjectProvider;
    kind: 'workflow' | 'operation';
    summary: string;
    match: {
        domains: string[];
        artifactTypes: string[];
        intents: string[];
    };
    accepts: string[];
    produces: string[];
    sideEffects: string[];
}
interface ProjectOverlayData {
    schemaVersion: number;
    entries?: ProjectEntry[];
    overrides?: Record<string, Override>;
    disabled?: string[];
}
interface ValidateProjectOverlayResult {
    ok: boolean;
    data?: ProjectOverlayData | BindingData | ProjectionData;
    diagnostics: Diagnostic[];
}
interface ValidateProjectOverlayDocumentResult<T> {
    ok: boolean;
    data?: T;
    diagnostics: Diagnostic[];
}
type ValidateProjectOverlayV1Result = ValidateProjectOverlayDocumentResult<ProjectOverlayData>;
declare function validateProjectOverlay(data: ProjectOverlayData): ValidateProjectOverlayV1Result;
declare function validateProjectOverlay(data: BindingData): ValidateProjectOverlayDocumentResult<BindingData>;
declare function validateProjectOverlay(data: ProjectionData): ValidateProjectOverlayDocumentResult<ProjectionData>;
declare function validateProjectOverlay(data: unknown): ValidateProjectOverlayResult;

interface DisabledEntry {
    ref: string;
    provider: Provider;
    sourceCatalog: string;
    disabledBy: string;
}

interface EffectiveEntry {
    ref: string;
    provider: Provider;
    kind: 'workflow' | 'operation';
    summary: string;
    match: {
        domains: string[];
        artifactTypes: string[];
        intents: string[];
    };
    accepts: string[];
    produces: string[];
    sideEffects: string[];
    provenance: {
        sourceCatalog: string;
        overriddenBy?: string;
    };
}
interface EffectiveIndex {
    schemaVersion: 1;
    inputs: {
        catalogs: Array<{
            id: string;
            version: string;
            contentHash: string;
        }>;
        projectContentHash: string;
    };
    entries: EffectiveEntry[];
    disabledEntries: DisabledEntry[];
}
interface BuildEffectiveIndexInput {
    catalogs?: unknown[];
    project?: unknown;
    familyApi?: unknown;
    implementations?: unknown[];
    inventory?: unknown;
    inventoryEntries?: unknown[];
    bindings?: unknown;
}
interface BuildEffectiveIndexV1Input {
    catalogs: unknown[];
    project?: unknown;
    familyApi?: never;
    implementations?: never;
    inventory?: never;
    bindings?: never;
}
interface BuildEffectiveIndexV2Input {
    familyApi: unknown;
    implementations?: unknown[];
    inventory?: unknown;
    inventoryEntries?: unknown[];
    bindings?: unknown;
    catalogs?: never;
    project?: never;
}
interface BuildEffectiveIndexResult {
    ok: boolean;
    index?: EffectiveIndex | ProjectionData;
    preparedInventory?: InventoryData;
    diagnostics: Diagnostic[];
}
interface BuildEffectiveIndexV1Result {
    ok: boolean;
    index?: EffectiveIndex;
    diagnostics: Diagnostic[];
}
interface BuildEffectiveIndexV2Result {
    ok: boolean;
    index?: ProjectionData;
    preparedInventory?: InventoryData;
    diagnostics: Diagnostic[];
}
/**
 * Build effective index from raw catalog and project overlay inputs.
 * - Validates each catalog via validateCatalog
 * - Validates project overlay via validateProjectOverlay
 * - Merges catalogs (conflict detection)
 * - Applies overlay (entries, overrides, disabled)
 * - Computes contentHashes via computeContentHash
 * - Sorts entries by ref, disabledEntries by ref
 * - Returns deterministic EffectiveIndex (no timestamps, no verification fields)
 */
declare function buildEffectiveIndex(input: BuildEffectiveIndexV1Input): BuildEffectiveIndexV1Result;
declare function buildEffectiveIndex(input: BuildEffectiveIndexV2Input): BuildEffectiveIndexV2Result;
declare function buildEffectiveIndex(input: BuildEffectiveIndexInput): BuildEffectiveIndexResult;

interface ValidateEffectiveIndexResult {
    ok: boolean;
    data?: unknown;
    diagnostics: Diagnostic[];
}

/**
 * Registry-private prepared-query capability.
 *
 * The authority boundary is an ECMAScript private field. A module-lexical
 * reader created inside the class body is the only code that can unwrap it.
 * Public properties, symbols, prototypes and ordinary digests are never used
 * as proof that Registry produced a handle.
 */

type FrozenMethodQuery = Readonly<{
    schemaVersion: 1;
    mode: 'standard';
    candidateServices: ReadonlyArray<Readonly<{
        serviceId: string;
        apiId: string;
        apiMajor: number;
        apiRevisionDigest: string;
    }>>;
    intent: string;
    kind: 'workflow' | 'operation';
    targetArtifact: Readonly<{
        type: string;
        id: string;
    }>;
    contractRevisionDigest: string;
    projectFactsEvidenceDigest: string;
    authorization: Readonly<{
        sideEffectBudget: string;
        granted: boolean;
    }>;
    registrySnapshot: Readonly<{
        digest: string;
        freshness: 'fresh' | 'stale' | 'missing';
    }>;
    queryDigest: string;
}>;
declare class PreparedMethodQueryHandle {
    #private;
    get candidateServices(): FrozenMethodQuery['candidateServices'];
    constructor(payload: FrozenMethodQuery);
    /** Return a detached diagnostic snapshot, never the authority payload. */
    data(): FrozenMethodQuery;
}

interface ProjectFactsEvidenceEnvelope {
    schemaVersion: 1;
    projectRoot: string;
    configDigest: string;
    policyDigest?: string | null;
    artifactGraphSummary: {
        artifactCount: number;
        edgeCount: number;
        contextTargets: string[];
    };
    targetArtifact: {
        type: string;
        id: string;
    };
    contractRevisionDigest: string;
    proofStatus: 'present' | 'missing' | 'stale';
    versionLockStatus: 'fresh' | 'stale' | 'missing';
    sourcesFreshness: 'fresh' | 'stale' | 'missing';
    bindingFreshness: 'fresh' | 'stale' | 'missing';
    evidenceDigest: string;
}
interface MethodQueryCandidate {
    mode: MethodQuery['mode'];
    intent: string;
    kind: MethodQuery['kind'];
    projectFactsEvidence: ProjectFactsEvidenceEnvelope;
    authorization: MethodQuery['authorization'];
}
interface QueryFilters {
    domain?: string;
    artifactType?: string;
    intent?: string;
    kind?: 'workflow' | 'operation';
    limit?: number;
    format?: 'compact' | 'full';
}
interface V1QueryInput extends QueryFilters {
    index: EffectiveIndex;
    methodQueryCandidate?: never;
    purpose?: never;
}
interface V2ForbiddenQueryFilters {
    domain?: never;
    artifactType?: never;
    intent?: never;
    kind?: never;
    limit?: never;
    format?: never;
}
interface V2RecommendationQueryInput extends V2ForbiddenQueryFilters {
    index: ProjectionData;
    methodQueryCandidate: MethodQueryCandidate;
    purpose: 'recommendation';
}
interface V2PrepareQueryInput extends V2ForbiddenQueryFilters {
    index: ProjectionData;
    methodQueryCandidate: MethodQueryCandidate;
    purpose: 'prepare';
}
type QueryInput = V1QueryInput | V2RecommendationQueryInput | V2PrepareQueryInput;
interface CompactEntry {
    ref: string;
    kind: 'workflow' | 'operation';
    summary: string;
}
/**
 * Recommendation-only entry: sanitized service metadata without authorization data.
 *
 * Discriminated by `executable`:
 * - `executable: true` — six orthogonal states are the unique executable combination;
 *   recommendation and prepare share the same derived gate, callers must not recompute it.
 * - `executable: false` — status fields use the Registry's published orthogonal literal types.
 */
interface ExecutableRecommendationEntry {
    ref: string;
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
    kind: 'workflow' | 'operation';
    summary: string;
    sideEffectCeiling: string;
    executable: true;
    installation: 'INSTALLED';
    enablement: 'ENABLED';
    compatibility: 'COMPATIBLE';
    trust: 'VERIFIED';
    resolution: 'EXPLICIT_BINDING';
    selectionSource: 'project-binding';
}
interface NonExecutableRecommendationEntry {
    ref: string;
    serviceId: string;
    apiId: string;
    apiMajor: number;
    apiRevisionDigest: string;
    kind: 'workflow' | 'operation';
    summary: string;
    sideEffectCeiling: string;
    executable: false;
    installation: Installation;
    enablement: Enablement;
    compatibility: Compatibility;
    trust: Trust;
    resolution: Resolution;
    selectionSource: SelectionSource;
}
type RecommendationEntry = ExecutableRecommendationEntry | NonExecutableRecommendationEntry;
interface QueryResultBase<Entry> {
    ok: boolean;
    data?: {
        entries: Entry[];
    };
    diagnostics: Diagnostic[];
}
interface V1QueryResult extends QueryResultBase<CompactEntry | EffectiveEntry> {
    preparedQueryHandle?: never;
}
interface RecommendationQueryResult extends QueryResultBase<RecommendationEntry> {
    preparedQueryHandle?: never;
}
interface PrepareQueryResult extends QueryResultBase<CompactEntry | ProjectionEntry> {
    preparedQueryHandle?: PreparedMethodQueryHandle;
}
type QueryResult = V1QueryResult | RecommendationQueryResult | PrepareQueryResult;
/**
 * Query an EffectiveIndex with structured filters.
 * - Validates index via validateEffectiveIndex first
 * - Filters by domain/artifactType/intent/kind (all optional, AND logic)
 * - Sorted by ref (already sorted in index)
 * - Limit: default 8
 * - compact mode: project {ref, kind, summary} only, verify 400 code points limit
 * - full mode: return complete EffectiveEntry
 * - No match -> ok:true with empty array + NO_QUERY_MATCH info diagnostic
 * - Invalid input -> INVALID_QUERY error
 */
declare function queryEffectiveIndex(input: V1QueryInput): V1QueryResult;
declare function queryEffectiveIndex(input: V2RecommendationQueryInput): RecommendationQueryResult;
declare function queryEffectiveIndex(input: V2PrepareQueryInput): PrepareQueryResult;

interface VerifyProviderV2Input {
    host: 'claude-code' | 'codex';
    provider?: never;
    runLock?: never;
    pluginRoots?: never;
    projectRoots?: never;
    v2: {
        implementation: ImplementationDescriptor;
        inventoryEntry: InventoryEntry;
        providerInstance: {
            scope: 'plugin' | 'project';
            pluginId: string;
            projectAuthority?: string;
            host: string;
            canonicalRoot: string;
            skillPath: string;
            packageDigest: string;
            bundleDigest: string;
            provenance: string;
        };
        inventorySnapshot: {
            digest: string;
            freshness: 'fresh' | 'stale' | 'missing';
        };
    };
}
interface VerifyProviderRunLockInput {
    host: 'claude-code' | 'codex';
    provider?: never;
    v2?: never;
    pluginRoots?: never;
    projectRoots?: never;
    runLock: RunMethodLock & {
        inventoryEntry: InventoryEntry;
    };
}
interface VerifyProviderV1Input {
    host?: 'claude-code' | 'codex';
    pluginRoots?: Record<string, string[]>;
    projectRoots?: string[];
    provider: Provider;
    v2?: never;
    runLock?: never;
}
type VerifyProviderInput = VerifyProviderV1Input | VerifyProviderV2Input | VerifyProviderRunLockInput;
interface VerifyProviderResult {
    status: 'verified' | 'not-found' | 'ambiguous' | 'unverified';
    diagnostics: Diagnostic[];
    observed?: {
        canonicalRoot?: string;
        skillRealpath?: string;
        bundleDigest?: string;
    };
}
/**
 * Verify provider discoverability.
 * - scope: plugin -> look up provider.plugin in pluginRoots, check <dir>/<skill>/SKILL.md
 * - scope: project -> use projectRoots, check <root>/<skill>/SKILL.md
 * - Dedup by canonical realpath (same file from different roots = single hit)
 * - 0 hits -> 'not-found' (PROVIDER_NOT_FOUND)
 * - 1 hit -> 'verified'
 * - >1 hits -> 'ambiguous' (AMBIGUOUS_PROVIDER)
 * - No matching root provided -> 'unverified'
 * - Does NOT recurse, only checks exact path <dir>/<skill>/SKILL.md
 */
interface ProviderVerification {
    status: 'verified' | 'not-found' | 'ambiguous' | 'unverified';
    diagnostics: Diagnostic[];
}
declare function verifyProvider(input: VerifyProviderInput): VerifyProviderResult;

interface ResolveInput {
    index: EffectiveIndex | ProjectionData;
    ref: string;
    host?: 'claude-code' | 'codex';
    pluginRoots?: Record<string, string[]>;
    projectRoots?: string[];
    strictProvider?: boolean;
    /** Registry-produced prepared query handle (v2 only); must come from queryEffectiveIndex. */
    preparedQueryHandle?: PreparedMethodQueryHandle;
    serviceIdentity?: ServiceIdentity;
}
interface ResolveResult {
    ok: boolean;
    data?: {
        entry: EffectiveEntry | ProjectionEntry;
        verification?: ProviderVerification;
        runMethodLock?: RunMethodLock;
    };
    diagnostics: Diagnostic[];
}
/**
 * Resolve a single logical ref to its provider.
 * - Validate index first
 * - Look up ref in entries -> not found -> ENTRY_NOT_FOUND
 * - Look up ref in disabledEntries -> found -> ENTRY_DISABLED
 * - If host + roots provided -> verify provider via verifyProvider
 * - If strictProvider and status='unverified' -> PROVIDER_UNVERIFIED error
 * - If roots/strictProvider present but no host -> HOST_REQUIRED
 * - PROVIDER_NOT_FOUND and AMBIGUOUS_PROVIDER are always errors when roots provided
 */
declare function resolveEntry(input: ResolveInput): ResolveResult;

interface DiagnoseV2Input {
    familyApi?: unknown;
    implementations?: unknown[];
    inventory?: unknown;
    bindings?: unknown;
    projection?: unknown;
    runLock?: unknown;
    migrationPlan?: unknown;
}
interface DiagnoseInput {
    catalogs: unknown[];
    project?: unknown;
    existingIndex?: EffectiveIndex;
    host?: 'claude-code' | 'codex';
    pluginRoots?: Record<string, string[]>;
    projectRoots?: string[];
    strictProvider?: boolean;
    v2?: DiagnoseV2Input;
}
interface DoctorCheck {
    id: 'schema' | 'merge' | 'freshness' | 'provider' | 'v2-schema' | 'v2-projection' | 'v2-snapshot';
    status: 'pass' | 'fail' | 'warn' | 'unverified';
    diagnostics: Diagnostic[];
    target?: string;
}
interface DiagnoseResult {
    ok: boolean;
    checks: DoctorCheck[];
    diagnostics: Diagnostic[];
}
declare function diagnoseRegistry(input: DiagnoseInput): DiagnoseResult;

export { type ApiRecognition, type BindingConversion, type BindingData, type BuildEffectiveIndexInput, type BuildEffectiveIndexResult, type BuildEffectiveIndexV1Input, type BuildEffectiveIndexV1Result, type BuildEffectiveIndexV2Input, type BuildEffectiveIndexV2Result, type CatalogData, type CollisionReport, type CompactEntry, type Compatibility, type DiagnoseInput, type DiagnoseResult, Diagnostic, type DisabledEntry, type DoctorCheck, type EffectiveEntry, type EffectiveIndex, type Enablement, type Entry, type ExecutableRecommendationEntry, type ImplementationDescriptor, type Installation, type InventoryData, type InventoryEntry, type MethodQuery, type MethodQueryCandidate, type MigrationPlan, type NonExecutableRecommendationEntry, type Override, type PluginProvider, type PrepareQueryResult, PreparedMethodQueryHandle as PreparedQueryHandle, type ProjectBindingData, type ProjectOverlayData, type ProjectProvider, type ProjectionData, type ProjectionEntry, type Provider, type ProviderVerification, type QueryInput, type QueryResult, type RecommendationEntry, type RecommendationQueryResult, type Resolution, type ResolveInput, type ResolveResult, type RunMethodLock, type SchemaValidationResult, type SelectionSource, type SyntheticIdentity, type Trust, type V1QueryInput, type V1QueryResult, type V2PrepareQueryInput, type V2RecommendationQueryInput, type ValidateCatalogDocumentResult, type ValidateCatalogResult, type ValidateCatalogV1Result, type ValidateEffectiveIndexResult, type ValidateProjectOverlayDocumentResult, type ValidateProjectOverlayResult, type ValidateProjectOverlayV1Result, type VerifyProviderInput, type VerifyProviderResult, type VerifyProviderRunLockInput, type VerifyProviderV1Input, type VerifyProviderV2Input, buildEffectiveIndex, diagnoseRegistry, queryEffectiveIndex, resolveEntry, validateCatalog, validateProjectOverlay, verifyProvider };
