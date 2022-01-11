package reconciler

import (
	pkgReconciler "github.com/joelanford/helm-operator/pkg/reconciler"
	"github.com/stackrox/rox/image"
	platform "github.com/stackrox/rox/operator/apis/platform/v1alpha1"
	commonExtensions "github.com/stackrox/rox/operator/pkg/common/extensions"
	"github.com/stackrox/rox/operator/pkg/proxy"
	"github.com/stackrox/rox/operator/pkg/reconciler"
	"github.com/stackrox/rox/operator/pkg/securedcluster/extensions"
	"github.com/stackrox/rox/operator/pkg/securedcluster/values/translation"
	"github.com/stackrox/rox/operator/pkg/utils"
	"github.com/stackrox/rox/pkg/version"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// RegisterNewReconciler registers a new helm reconciler in the given k8s controller manager
func RegisterNewReconciler(mgr ctrl.Manager) error {
	proxyEnv := proxy.GetProxyEnvVars() // fix at startup time
	return reconciler.SetupReconcilerWithManager(
		mgr, platform.SecuredClusterGVK,
		image.SecuredClusterServicesChartPrefix,
		proxy.InjectProxyEnvVars(translation.NewTranslator(mgr.GetClient()), proxyEnv),
		pkgReconciler.WithExtraWatch(
			&source.Kind{Type: &platform.Central{}},
			handleSiblingSecuredClusters(mgr),
			// Only appearance and disappearance of a Central resource can influence whether
			// a local scanner should be deployed by the SecuredCluster controller.
			utils.CreateAndDeleteOnlyPredicate{}),
		pkgReconciler.WithPreExtension(extensions.CheckClusterNameExtension(nil)),
		// TODO(ROX-8825): generalize and run ReconcileScannerDBPasswordExtension here
		pkgReconciler.WithPreExtension(proxy.ReconcileProxySecretExtension(mgr.GetClient(), proxyEnv)),
		pkgReconciler.WithPreExtension(commonExtensions.CheckForbiddenNamespacesExtension(commonExtensions.IsSystemNamespace)),
		pkgReconciler.WithPreExtension(commonExtensions.ReconcileProductVersionStatusExtension(version.GetMainVersion())),
	)
}
