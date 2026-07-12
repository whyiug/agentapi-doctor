package main

type SupportManifest struct {
	SchemaVersion  string            `json:"schemaVersion"`
	Kind           string            `json:"kind"`
	ManifestStatus string            `json:"manifestStatus"`
	D30Catalog     map[string]string `json:"d30Catalog"`
	Cells          []SupportCell     `json:"cells"`
}

type SupportCell struct {
	ID              string            `json:"id"`
	Artifact        ArtifactRef       `json:"artifact"`
	Tier            string            `json:"tier"`
	MaturityTarget  string            `json:"maturityTarget"`
	VersionPolicy   VersionPolicy     `json:"versionPolicy"`
	Platforms       Platforms         `json:"platforms"`
	CICadence       []string          `json:"ciCadence"`
	ReleaseBlocking bool              `json:"releaseBlocking"`
	Ownership       Ownership         `json:"ownership"`
	UpdateSLA       UpdateSLA         `json:"updateSLA"`
	KnownGapPolicy  string            `json:"knownGapPolicy"`
	D30Criteria     []string          `json:"d30Criteria"`
	TierGates       map[string]string `json:"tierGates"`
}

type ArtifactRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type VersionPolicy struct {
	Applicability           string   `json:"applicability"`
	Selectors               []string `json:"selectors"`
	ExactResolutionRequired bool     `json:"exactResolutionRequired"`
}

type Platforms struct {
	OS   []string `json:"os"`
	Arch []string `json:"arch"`
}

type Ownership struct {
	Primary OwnerSlot `json:"primary"`
	Backup  OwnerSlot `json:"backup"`
}

type OwnerSlot struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}

type UpdateSLA struct {
	Days  int64  `json:"days"`
	Clock string `json:"clock"`
}

type SupportLock struct {
	SchemaVersion         string     `json:"schemaVersion"`
	Kind                  string     `json:"kind"`
	LockStatus            string     `json:"lockStatus"`
	Release               string     `json:"release"`
	SupportManifestDigest *string    `json:"supportManifestDigest"`
	ResolutionPolicy      string     `json:"resolutionPolicy"`
	Cells                 []LockCell `json:"cells"`
}

type LockCell struct {
	CellID            string        `json:"cellId"`
	Status            string        `json:"status"`
	ReasonCode        string        `json:"reasonCode"`
	ArtifactVersion   *string       `json:"artifactVersion"`
	ArtifactDigest    *string       `json:"artifactDigest"`
	DenominatorDigest *string       `json:"denominatorDigest"`
	VersionSlots      []VersionSlot `json:"versionSlots"`
	GateStatus        string        `json:"gateStatus"`
	EvidenceRefs      []string      `json:"evidenceRefs"`
}

type VersionSlot struct {
	Slot           string   `json:"slot"`
	Status         string   `json:"status"`
	ExactVersion   *string  `json:"exactVersion"`
	PackageDigest  *string  `json:"packageDigest"`
	RuntimeVersion *string  `json:"runtimeVersion"`
	ImageDigest    *string  `json:"imageDigest"`
	LockfileDigest *string  `json:"lockfileDigest"`
	EvidenceRefs   []string `json:"evidenceRefs"`
}

type ReleaseComponents struct {
	SchemaVersion  string             `json:"schemaVersion"`
	Kind           string             `json:"kind"`
	ReleaseTarget  string             `json:"releaseTarget"`
	ManifestStatus string             `json:"manifestStatus"`
	Components     []ReleaseComponent `json:"components"`
}

type ReleaseComponent struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Required       bool     `json:"required"`
	TargetMaturity string   `json:"targetMaturity"`
	Status         string   `json:"status"`
	D30Criteria    []string `json:"d30Criteria"`
}

type ConsumerProfile struct {
	SchemaVersion string       `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Status        string       `json:"status"`
	Metadata      ArtifactMeta `json:"metadata"`
	Spec          ConsumerSpec `json:"spec"`
}

type ArtifactMeta struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ConsumerSpec struct {
	Consumer             ConsumerIdentity `json:"consumer"`
	DriverRef            string           `json:"driverRef"`
	ProtocolPacks        []string         `json:"protocolPacks"`
	APITypes             []string         `json:"apiTypes"`
	ForbiddenFallbacks   []string         `json:"forbiddenFallbacks,omitempty"`
	ExcludedAPITypes     []string         `json:"excludedApiTypes,omitempty"`
	RequiredCapabilities []string         `json:"requiredCapabilities"`
	Sandbox              SandboxPolicy    `json:"sandbox"`
	SupportGate          PendingGate      `json:"supportGate"`
}

type ConsumerIdentity struct {
	Name                      string   `json:"name"`
	Category                  string   `json:"category"`
	UpstreamVersionResolution string   `json:"upstreamVersionResolution"`
	ExactVersions             []string `json:"exactVersions"`
}

type SandboxPolicy struct {
	TemporaryHome      bool   `json:"temporaryHome"`
	TemporaryGitRepo   bool   `json:"temporaryGitRepo,omitempty"`
	Network            string `json:"network"`
	AmbientCredentials bool   `json:"ambientCredentials"`
	SyntheticToolsOnly bool   `json:"syntheticToolsOnly,omitempty"`
}

type PendingGate struct {
	Status       string   `json:"status"`
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidenceRefs"`
}

type DriverManifest struct {
	SchemaVersion string       `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Status        string       `json:"status"`
	Metadata      ArtifactMeta `json:"metadata"`
	Spec          DriverSpec   `json:"spec"`
}

type DriverSpec struct {
	RPC          DriverRPC       `json:"rpc"`
	Execution    DriverExecution `json:"execution"`
	Capabilities []string        `json:"capabilities"`
	Permissions  []string        `json:"permissions"`
	Security     DriverSecurity  `json:"security"`
	Gate         PendingGate     `json:"gate"`
}

type DriverRPC struct {
	Minimum               string `json:"minimum"`
	Maximum               string `json:"maximum"`
	Transport             string `json:"transport"`
	MaxControlFrameBytes  int64  `json:"maxControlFrameBytes"`
	DefaultDataFrameBytes int64  `json:"defaultDataFrameBytes"`
}

type DriverExecution struct {
	Type                string  `json:"type"`
	Runtime             string  `json:"runtime"`
	ResolutionStatus    string  `json:"resolutionStatus"`
	ExactRuntimeVersion *string `json:"exactRuntimeVersion"`
	ArtifactDigest      *string `json:"artifactDigest"`
	LockfileDigest      *string `json:"lockfileDigest"`
	ImageDigest         *string `json:"imageDigest"`
}

type DriverSecurity struct {
	ReceivesRealAuth   bool   `json:"receivesRealAuth"`
	CASWrite           bool   `json:"casWrite"`
	StdoutProtocolOnly bool   `json:"stdoutProtocolOnly"`
	Network            string `json:"network"`
}

type RuntimeAdapter struct {
	SchemaVersion string       `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Status        string       `json:"status"`
	Metadata      ArtifactMeta `json:"metadata"`
	Spec          RuntimeSpec  `json:"spec"`
}

type RuntimeSpec struct {
	Runtime         RuntimeIdentity `json:"runtime"`
	Behavior        AdapterBehavior `json:"behavior"`
	OutputFields    []string        `json:"outputFields"`
	FixtureContract FixtureContract `json:"fixtureContract"`
	Gate            PendingGate     `json:"gate"`
}

type RuntimeIdentity struct {
	Name              string   `json:"name"`
	VersionResolution string   `json:"versionResolution"`
	ExactVersions     []string `json:"exactVersions"`
}

type AdapterBehavior struct {
	SendsClientRequests      bool `json:"sendsClientRequests"`
	ModifiesNormativeTruth   bool `json:"modifiesNormativeTruth"`
	ProtocolConformanceLabel bool `json:"protocolConformanceLabel"`
}

type FixtureContract struct {
	Valid           string   `json:"valid"`
	Invalid         string   `json:"invalid"`
	RequiredFields  []string `json:"requiredFields"`
	ForbiddenFields []string `json:"forbiddenFields"`
}

type ExternalAdapter struct {
	SchemaVersion string       `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Status        string       `json:"status"`
	Metadata      ArtifactMeta `json:"metadata"`
	Spec          ExternalSpec `json:"spec"`
}

type ExternalSpec struct {
	Upstream    ExternalUpstream  `json:"upstream"`
	Interface   ExternalInterface `json:"interface"`
	RunEvidence ExternalRun       `json:"runEvidence"`
	Gate        PendingGate       `json:"gate"`
}

type ExternalUpstream struct {
	Project          string  `json:"project"`
	Repository       string  `json:"repository"`
	ResolutionStatus string  `json:"resolutionStatus"`
	ExactVersion     *string `json:"exactVersion"`
	SourceDigest     *string `json:"sourceDigest"`
	LicenseStatus    string  `json:"licenseStatus"`
}

type ExternalInterface struct {
	Transport     string `json:"transport"`
	InputSchema   string `json:"inputSchema"`
	OutputSchema  string `json:"outputSchema"`
	MappingPolicy string `json:"mappingPolicy"`
	Network       string `json:"network"`
}

type ExternalRun struct {
	Status       string   `json:"status"`
	ResultDigest *string  `json:"resultDigest"`
	EvidenceRefs []string `json:"evidenceRefs"`
}
