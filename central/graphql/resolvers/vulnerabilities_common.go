package resolvers

import (
	"context"

	"github.com/graph-gophers/graphql-go"
)

// VulnerabilityMetadata represents the supported API on all vulnerabilities
type VulnerabilityMetadata interface {
	ID(ctx context.Context) graphql.ID
	CVE(ctx context.Context) string
	Cvss(ctx context.Context) float64
	ScoreVersion(ctx context.Context) string
	Vectors() *EmbeddedVulnerabilityVectorsResolver
	Link(ctx context.Context) string
	Summary(ctx context.Context) string
	FixedByVersion(ctx context.Context) (string, error)
	IsFixable(ctx context.Context, args RawQuery) (bool, error)
	LastScanned(ctx context.Context) (*graphql.Time, error)
	CreatedAt(ctx context.Context) (*graphql.Time, error)
	EnvImpact(ctx context.Context) (float64, error)
	Severity(ctx context.Context) string
	PublishedOn(ctx context.Context) (*graphql.Time, error)
	LastModified(ctx context.Context) (*graphql.Time, error)
	ImpactScore(ctx context.Context) float64
	Suppressed(ctx context.Context) bool
	SuppressActivation(ctx context.Context) (*graphql.Time, error)
	SuppressExpiry(ctx context.Context) (*graphql.Time, error)
	ActiveState(ctx context.Context, args RawQuery) (*activeStateResolver, error)

	// this function searches for image vulns specifically, so can probably scope to just image?
	VulnerabilityState(ctx context.Context) string

	UnusedVarSink(ctx context.Context, args RawQuery) *int32
}
