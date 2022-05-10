package backend

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/clusterinit/backend/certificate"
	"github.com/stackrox/rox/central/clusterinit/store"
	"github.com/stackrox/rox/central/clusters"
	"github.com/stackrox/rox/central/role/resources"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/auth/permissions"
	"github.com/stackrox/rox/pkg/grpc/authn"
	"github.com/stackrox/rox/pkg/grpc/authz/and"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
)

// CAConfig is the configuration for the StackRox Service CA.
type CAConfig struct {
	CACert string
}

// InitBundleWithMeta contains an init bundle alongside its meta data.
type InitBundleWithMeta struct {
	CAConfig
	CertBundle clusters.CertBundle
	Meta       *storage.InitBundleMeta
}

var (
	// ErrInitBundleIsRevoked signals that an init bundle has been revoked.
	ErrInitBundleIsRevoked = errors.New("init bundle is revoked")
)

// Backend is the backend for the cluster-init component.
//go:generate mockgen-wrapper
type Backend interface {
	GetAll(ctx context.Context) ([]*storage.InitBundleMeta, error)
	GetCAConfig(ctx context.Context) (*CAConfig, error)
	Issue(ctx context.Context, name string) (*InitBundleWithMeta, error)
	Revoke(ctx context.Context, id string) error
	CheckRevoked(ctx context.Context, id string) error
	authn.ValidateCertChain
}

func newBackend(store store.Store, certProvider certificate.Provider) Backend {
	return &backendImpl{
		store:        store,
		certProvider: certProvider,
	}
}

// CheckAccess returns nil if requested access level is granted in context.
func CheckAccess(ctx context.Context, access storage.Access) error {
	authZ := and.And(
		user.With(permissions.ResourceWithAccess{Resource: resources.ServiceIdentity, Access: access}),
		user.With(permissions.ResourceWithAccess{Resource: resources.APIToken, Access: access}),
	)

	return authZ.Authorized(ctx, "")
}
