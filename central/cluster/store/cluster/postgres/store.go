// Code generated by pg-bindings generator. DO NOT EDIT.

package postgres

import (
	"context"
<<<<<<< HEAD
	"reflect"
=======
	"fmt"
>>>>>>> c95a9b179 (WIP)
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/generated/storage"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

const (
	baseTable  = "clusters"
	countStmt  = "SELECT COUNT(*) FROM clusters"
	existsStmt = "SELECT EXISTS(SELECT 1 FROM clusters WHERE Id = $1 AND HealthStatus_Id = $2)"

	getStmt    = "SELECT serialized FROM clusters WHERE Id = $1 AND HealthStatus_Id = $2"
	deleteStmt = "DELETE FROM clusters WHERE Id = $1 AND HealthStatus_Id = $2"
	walkStmt   = "SELECT serialized FROM clusters"
)

var (
	schema = walker.Walk(reflect.TypeOf((*storage.Cluster)(nil)), baseTable)
)

func init() {
	globaldb.RegisterTable(schema)
}

type Store interface {
	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, id string, healthStatusId string) (bool, error)
	Get(ctx context.Context, id string, healthStatusId string) (*storage.Cluster, bool, error)
	Upsert(ctx context.Context, obj *storage.Cluster) error
	UpsertMany(ctx context.Context, objs []*storage.Cluster) error
	Delete(ctx context.Context, id string, healthStatusId string) error

	Walk(ctx context.Context, fn func(obj *storage.Cluster) error) error

	AckKeysIndexed(ctx context.Context, keys ...string) error
	GetKeysToIndex(ctx context.Context) ([]string, error)
}

type storeImpl struct {
	db *pgxpool.Pool
}

func createTableClusters(ctx context.Context, db *pgxpool.Pool) {
	table := `
create table if not exists clusters (
    Id varchar,
    Name varchar UNIQUE,
    Type integer,
    Labels jsonb,
    MainImage varchar,
    CollectorImage varchar,
    CentralApiEndpoint varchar,
    RuntimeSupport bool,
    CollectionMethod integer,
    AdmissionController bool,
    AdmissionControllerUpdates bool,
    AdmissionControllerEvents bool,
    Status_SensorVersion varchar,
    Status_DEPRECATEDLastContact timestamp,
    Status_ProviderMetadata_Region varchar,
    Status_ProviderMetadata_Zone varchar,
    Status_ProviderMetadata_Google_Project varchar,
    Status_ProviderMetadata_Google_ClusterName varchar,
    Status_ProviderMetadata_Aws_AccountId varchar,
    Status_ProviderMetadata_Azure_SubscriptionId varchar,
    Status_ProviderMetadata_Verified bool,
    Status_OrchestratorMetadata_Version varchar,
    Status_OrchestratorMetadata_OpenshiftVersion varchar,
    Status_OrchestratorMetadata_BuildDate timestamp,
    Status_OrchestratorMetadata_ApiVersions text[],
    Status_UpgradeStatus_Upgradability integer,
    Status_UpgradeStatus_UpgradabilityStatusReason varchar,
    Status_UpgradeStatus_MostRecentProcess_Active bool,
    Status_UpgradeStatus_MostRecentProcess_Id varchar,
    Status_UpgradeStatus_MostRecentProcess_TargetVersion varchar,
    Status_UpgradeStatus_MostRecentProcess_UpgraderImage varchar,
    Status_UpgradeStatus_MostRecentProcess_InitiatedAt timestamp,
    Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeState integer,
    Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeStatusDetail varchar,
    Status_UpgradeStatus_MostRecentProcess_Progress_Since timestamp,
    Status_UpgradeStatus_MostRecentProcess_Type integer,
    Status_CertExpiryStatus_SensorCertExpiry timestamp,
    Status_CertExpiryStatus_SensorCertNotBefore timestamp,
    DynamicConfig_AdmissionControllerConfig_Enabled bool,
    DynamicConfig_AdmissionControllerConfig_TimeoutSeconds integer,
    DynamicConfig_AdmissionControllerConfig_ScanInline bool,
    DynamicConfig_AdmissionControllerConfig_DisableBypass bool,
    DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates bool,
    DynamicConfig_RegistryOverride varchar,
    DynamicConfig_DisableAuditLogs bool,
    TolerationsConfig_Disabled bool,
    Priority integer,
    HealthStatus_Id varchar,
    HealthStatus_CollectorHealthInfo_Version varchar,
    HealthStatus_CollectorHealthInfo_TotalDesiredPods integer,
    HealthStatus_CollectorHealthInfo_TotalReadyPods integer,
    HealthStatus_CollectorHealthInfo_TotalRegisteredNodes integer,
    HealthStatus_CollectorHealthInfo_StatusErrors text[],
    HealthStatus_AdmissionControlHealthInfo_TotalDesiredPods integer,
    HealthStatus_AdmissionControlHealthInfo_TotalReadyPods integer,
    HealthStatus_AdmissionControlHealthInfo_StatusErrors text[],
    HealthStatus_SensorHealthStatus integer,
    HealthStatus_CollectorHealthStatus integer,
    HealthStatus_OverallHealthStatus integer,
    HealthStatus_AdmissionControlHealthStatus integer,
    HealthStatus_LastContact timestamp,
    HealthStatus_HealthInfoComplete bool,
    SlimCollector bool,
    HelmConfig_DynamicConfig_AdmissionControllerConfig_Enabled bool,
    HelmConfig_DynamicConfig_AdmissionControllerConfig_TimeoutSeconds integer,
    HelmConfig_DynamicConfig_AdmissionControllerConfig_ScanInline bool,
    HelmConfig_DynamicConfig_AdmissionControllerConfig_DisableBypass bool,
    HelmConfig_DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates bool,
    HelmConfig_DynamicConfig_RegistryOverride varchar,
    HelmConfig_DynamicConfig_DisableAuditLogs bool,
    HelmConfig_StaticConfig_Type integer,
    HelmConfig_StaticConfig_MainImage varchar,
    HelmConfig_StaticConfig_CentralApiEndpoint varchar,
    HelmConfig_StaticConfig_CollectionMethod integer,
    HelmConfig_StaticConfig_CollectorImage varchar,
    HelmConfig_StaticConfig_AdmissionController bool,
    HelmConfig_StaticConfig_AdmissionControllerUpdates bool,
    HelmConfig_StaticConfig_TolerationsConfig_Disabled bool,
    HelmConfig_StaticConfig_SlimCollector bool,
    HelmConfig_StaticConfig_AdmissionControllerEvents bool,
    HelmConfig_ConfigFingerprint varchar,
    HelmConfig_ClusterLabels jsonb,
    MostRecentSensorId_SystemNamespaceId varchar,
    MostRecentSensorId_DefaultNamespaceId varchar,
    MostRecentSensorId_AppNamespace varchar,
    MostRecentSensorId_AppNamespaceId varchar,
    MostRecentSensorId_AppServiceaccountId varchar,
    MostRecentSensorId_K8SNodeName varchar,
    AuditLogState jsonb,
    InitBundleId varchar,
    ManagedBy integer,
    serialized bytea,
    PRIMARY KEY(Id, HealthStatus_Id)
)
`

	_, err := db.Exec(ctx, table)
	if err != nil {
		panic(fmt.Sprintf("error creating table %s: %v", table, err))
	}

	indexes := []string{}
	for _, index := range indexes {
		if _, err := db.Exec(ctx, index); err != nil {
			panic(err)
		}
	}

}

func insertIntoClusters(ctx context.Context, tx pgx.Tx, obj *storage.Cluster) error {

	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		obj.GetId(),
		obj.GetName(),
		obj.GetType(),
		obj.GetLabels(),
		obj.GetMainImage(),
		obj.GetCollectorImage(),
		obj.GetCentralApiEndpoint(),
		obj.GetRuntimeSupport(),
		obj.GetCollectionMethod(),
		obj.GetAdmissionController(),
		obj.GetAdmissionControllerUpdates(),
		obj.GetAdmissionControllerEvents(),
		obj.GetStatus().GetSensorVersion(),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetDEPRECATEDLastContact()),
		obj.GetStatus().GetProviderMetadata().GetRegion(),
		obj.GetStatus().GetProviderMetadata().GetZone(),
		obj.GetStatus().GetProviderMetadata().GetGoogle().GetProject(),
		obj.GetStatus().GetProviderMetadata().GetGoogle().GetClusterName(),
		obj.GetStatus().GetProviderMetadata().GetAws().GetAccountId(),
		obj.GetStatus().GetProviderMetadata().GetAzure().GetSubscriptionId(),
		obj.GetStatus().GetProviderMetadata().GetVerified(),
		obj.GetStatus().GetOrchestratorMetadata().GetVersion(),
		obj.GetStatus().GetOrchestratorMetadata().GetOpenshiftVersion(),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetOrchestratorMetadata().GetBuildDate()),
		obj.GetStatus().GetOrchestratorMetadata().GetApiVersions(),
		obj.GetStatus().GetUpgradeStatus().GetUpgradability(),
		obj.GetStatus().GetUpgradeStatus().GetUpgradabilityStatusReason(),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetActive(),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetId(),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetTargetVersion(),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetUpgraderImage(),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetInitiatedAt()),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetProgress().GetUpgradeState(),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetProgress().GetUpgradeStatusDetail(),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetProgress().GetSince()),
		obj.GetStatus().GetUpgradeStatus().GetMostRecentProcess().GetType(),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetCertExpiryStatus().GetSensorCertExpiry()),
		pgutils.NilOrStringTimestamp(obj.GetStatus().GetCertExpiryStatus().GetSensorCertNotBefore()),
		obj.GetDynamicConfig().GetAdmissionControllerConfig().GetEnabled(),
		obj.GetDynamicConfig().GetAdmissionControllerConfig().GetTimeoutSeconds(),
		obj.GetDynamicConfig().GetAdmissionControllerConfig().GetScanInline(),
		obj.GetDynamicConfig().GetAdmissionControllerConfig().GetDisableBypass(),
		obj.GetDynamicConfig().GetAdmissionControllerConfig().GetEnforceOnUpdates(),
		obj.GetDynamicConfig().GetRegistryOverride(),
		obj.GetDynamicConfig().GetDisableAuditLogs(),
		obj.GetTolerationsConfig().GetDisabled(),
		obj.GetPriority(),
		obj.GetHealthStatus().GetId(),
		obj.GetHealthStatus().GetCollectorHealthInfo().GetVersion(),
		obj.GetHealthStatus().GetCollectorHealthInfo().GetTotalDesiredPods(),
		obj.GetHealthStatus().GetCollectorHealthInfo().GetTotalReadyPods(),
		obj.GetHealthStatus().GetCollectorHealthInfo().GetTotalRegisteredNodes(),
		obj.GetHealthStatus().GetCollectorHealthInfo().GetStatusErrors(),
		obj.GetHealthStatus().GetAdmissionControlHealthInfo().GetTotalDesiredPods(),
		obj.GetHealthStatus().GetAdmissionControlHealthInfo().GetTotalReadyPods(),
		obj.GetHealthStatus().GetAdmissionControlHealthInfo().GetStatusErrors(),
		obj.GetHealthStatus().GetSensorHealthStatus(),
		obj.GetHealthStatus().GetCollectorHealthStatus(),
		obj.GetHealthStatus().GetOverallHealthStatus(),
		obj.GetHealthStatus().GetAdmissionControlHealthStatus(),
		pgutils.NilOrStringTimestamp(obj.GetHealthStatus().GetLastContact()),
		obj.GetHealthStatus().GetHealthInfoComplete(),
		obj.GetSlimCollector(),
		obj.GetHelmConfig().GetDynamicConfig().GetAdmissionControllerConfig().GetEnabled(),
		obj.GetHelmConfig().GetDynamicConfig().GetAdmissionControllerConfig().GetTimeoutSeconds(),
		obj.GetHelmConfig().GetDynamicConfig().GetAdmissionControllerConfig().GetScanInline(),
		obj.GetHelmConfig().GetDynamicConfig().GetAdmissionControllerConfig().GetDisableBypass(),
		obj.GetHelmConfig().GetDynamicConfig().GetAdmissionControllerConfig().GetEnforceOnUpdates(),
		obj.GetHelmConfig().GetDynamicConfig().GetRegistryOverride(),
		obj.GetHelmConfig().GetDynamicConfig().GetDisableAuditLogs(),
		obj.GetHelmConfig().GetStaticConfig().GetType(),
		obj.GetHelmConfig().GetStaticConfig().GetMainImage(),
		obj.GetHelmConfig().GetStaticConfig().GetCentralApiEndpoint(),
		obj.GetHelmConfig().GetStaticConfig().GetCollectionMethod(),
		obj.GetHelmConfig().GetStaticConfig().GetCollectorImage(),
		obj.GetHelmConfig().GetStaticConfig().GetAdmissionController(),
		obj.GetHelmConfig().GetStaticConfig().GetAdmissionControllerUpdates(),
		obj.GetHelmConfig().GetStaticConfig().GetTolerationsConfig().GetDisabled(),
		obj.GetHelmConfig().GetStaticConfig().GetSlimCollector(),
		obj.GetHelmConfig().GetStaticConfig().GetAdmissionControllerEvents(),
		obj.GetHelmConfig().GetConfigFingerprint(),
		obj.GetHelmConfig().GetClusterLabels(),
		obj.GetMostRecentSensorId().GetSystemNamespaceId(),
		obj.GetMostRecentSensorId().GetDefaultNamespaceId(),
		obj.GetMostRecentSensorId().GetAppNamespace(),
		obj.GetMostRecentSensorId().GetAppNamespaceId(),
		obj.GetMostRecentSensorId().GetAppServiceaccountId(),
		obj.GetMostRecentSensorId().GetK8SNodeName(),
		obj.GetAuditLogState(),
		obj.GetInitBundleId(),
		obj.GetManagedBy(),
		serialized,
	}

	finalStr := "INSERT INTO clusters (Id, Name, Type, Labels, MainImage, CollectorImage, CentralApiEndpoint, RuntimeSupport, CollectionMethod, AdmissionController, AdmissionControllerUpdates, AdmissionControllerEvents, Status_SensorVersion, Status_DEPRECATEDLastContact, Status_ProviderMetadata_Region, Status_ProviderMetadata_Zone, Status_ProviderMetadata_Google_Project, Status_ProviderMetadata_Google_ClusterName, Status_ProviderMetadata_Aws_AccountId, Status_ProviderMetadata_Azure_SubscriptionId, Status_ProviderMetadata_Verified, Status_OrchestratorMetadata_Version, Status_OrchestratorMetadata_OpenshiftVersion, Status_OrchestratorMetadata_BuildDate, Status_OrchestratorMetadata_ApiVersions, Status_UpgradeStatus_Upgradability, Status_UpgradeStatus_UpgradabilityStatusReason, Status_UpgradeStatus_MostRecentProcess_Active, Status_UpgradeStatus_MostRecentProcess_Id, Status_UpgradeStatus_MostRecentProcess_TargetVersion, Status_UpgradeStatus_MostRecentProcess_UpgraderImage, Status_UpgradeStatus_MostRecentProcess_InitiatedAt, Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeState, Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeStatusDetail, Status_UpgradeStatus_MostRecentProcess_Progress_Since, Status_UpgradeStatus_MostRecentProcess_Type, Status_CertExpiryStatus_SensorCertExpiry, Status_CertExpiryStatus_SensorCertNotBefore, DynamicConfig_AdmissionControllerConfig_Enabled, DynamicConfig_AdmissionControllerConfig_TimeoutSeconds, DynamicConfig_AdmissionControllerConfig_ScanInline, DynamicConfig_AdmissionControllerConfig_DisableBypass, DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates, DynamicConfig_RegistryOverride, DynamicConfig_DisableAuditLogs, TolerationsConfig_Disabled, Priority, HealthStatus_Id, HealthStatus_CollectorHealthInfo_Version, HealthStatus_CollectorHealthInfo_TotalDesiredPods, HealthStatus_CollectorHealthInfo_TotalReadyPods, HealthStatus_CollectorHealthInfo_TotalRegisteredNodes, HealthStatus_CollectorHealthInfo_StatusErrors, HealthStatus_AdmissionControlHealthInfo_TotalDesiredPods, HealthStatus_AdmissionControlHealthInfo_TotalReadyPods, HealthStatus_AdmissionControlHealthInfo_StatusErrors, HealthStatus_SensorHealthStatus, HealthStatus_CollectorHealthStatus, HealthStatus_OverallHealthStatus, HealthStatus_AdmissionControlHealthStatus, HealthStatus_LastContact, HealthStatus_HealthInfoComplete, SlimCollector, HelmConfig_DynamicConfig_AdmissionControllerConfig_Enabled, HelmConfig_DynamicConfig_AdmissionControllerConfig_TimeoutSeconds, HelmConfig_DynamicConfig_AdmissionControllerConfig_ScanInline, HelmConfig_DynamicConfig_AdmissionControllerConfig_DisableBypass, HelmConfig_DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates, HelmConfig_DynamicConfig_RegistryOverride, HelmConfig_DynamicConfig_DisableAuditLogs, HelmConfig_StaticConfig_Type, HelmConfig_StaticConfig_MainImage, HelmConfig_StaticConfig_CentralApiEndpoint, HelmConfig_StaticConfig_CollectionMethod, HelmConfig_StaticConfig_CollectorImage, HelmConfig_StaticConfig_AdmissionController, HelmConfig_StaticConfig_AdmissionControllerUpdates, HelmConfig_StaticConfig_TolerationsConfig_Disabled, HelmConfig_StaticConfig_SlimCollector, HelmConfig_StaticConfig_AdmissionControllerEvents, HelmConfig_ConfigFingerprint, HelmConfig_ClusterLabels, MostRecentSensorId_SystemNamespaceId, MostRecentSensorId_DefaultNamespaceId, MostRecentSensorId_AppNamespace, MostRecentSensorId_AppNamespaceId, MostRecentSensorId_AppServiceaccountId, MostRecentSensorId_K8SNodeName, AuditLogState, InitBundleId, ManagedBy, serialized) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, $80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $90, $91, $92) ON CONFLICT(Id, HealthStatus_Id) DO UPDATE SET Id = EXCLUDED.Id, Name = EXCLUDED.Name, Type = EXCLUDED.Type, Labels = EXCLUDED.Labels, MainImage = EXCLUDED.MainImage, CollectorImage = EXCLUDED.CollectorImage, CentralApiEndpoint = EXCLUDED.CentralApiEndpoint, RuntimeSupport = EXCLUDED.RuntimeSupport, CollectionMethod = EXCLUDED.CollectionMethod, AdmissionController = EXCLUDED.AdmissionController, AdmissionControllerUpdates = EXCLUDED.AdmissionControllerUpdates, AdmissionControllerEvents = EXCLUDED.AdmissionControllerEvents, Status_SensorVersion = EXCLUDED.Status_SensorVersion, Status_DEPRECATEDLastContact = EXCLUDED.Status_DEPRECATEDLastContact, Status_ProviderMetadata_Region = EXCLUDED.Status_ProviderMetadata_Region, Status_ProviderMetadata_Zone = EXCLUDED.Status_ProviderMetadata_Zone, Status_ProviderMetadata_Google_Project = EXCLUDED.Status_ProviderMetadata_Google_Project, Status_ProviderMetadata_Google_ClusterName = EXCLUDED.Status_ProviderMetadata_Google_ClusterName, Status_ProviderMetadata_Aws_AccountId = EXCLUDED.Status_ProviderMetadata_Aws_AccountId, Status_ProviderMetadata_Azure_SubscriptionId = EXCLUDED.Status_ProviderMetadata_Azure_SubscriptionId, Status_ProviderMetadata_Verified = EXCLUDED.Status_ProviderMetadata_Verified, Status_OrchestratorMetadata_Version = EXCLUDED.Status_OrchestratorMetadata_Version, Status_OrchestratorMetadata_OpenshiftVersion = EXCLUDED.Status_OrchestratorMetadata_OpenshiftVersion, Status_OrchestratorMetadata_BuildDate = EXCLUDED.Status_OrchestratorMetadata_BuildDate, Status_OrchestratorMetadata_ApiVersions = EXCLUDED.Status_OrchestratorMetadata_ApiVersions, Status_UpgradeStatus_Upgradability = EXCLUDED.Status_UpgradeStatus_Upgradability, Status_UpgradeStatus_UpgradabilityStatusReason = EXCLUDED.Status_UpgradeStatus_UpgradabilityStatusReason, Status_UpgradeStatus_MostRecentProcess_Active = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Active, Status_UpgradeStatus_MostRecentProcess_Id = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Id, Status_UpgradeStatus_MostRecentProcess_TargetVersion = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_TargetVersion, Status_UpgradeStatus_MostRecentProcess_UpgraderImage = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_UpgraderImage, Status_UpgradeStatus_MostRecentProcess_InitiatedAt = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_InitiatedAt, Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeState = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeState, Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeStatusDetail = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Progress_UpgradeStatusDetail, Status_UpgradeStatus_MostRecentProcess_Progress_Since = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Progress_Since, Status_UpgradeStatus_MostRecentProcess_Type = EXCLUDED.Status_UpgradeStatus_MostRecentProcess_Type, Status_CertExpiryStatus_SensorCertExpiry = EXCLUDED.Status_CertExpiryStatus_SensorCertExpiry, Status_CertExpiryStatus_SensorCertNotBefore = EXCLUDED.Status_CertExpiryStatus_SensorCertNotBefore, DynamicConfig_AdmissionControllerConfig_Enabled = EXCLUDED.DynamicConfig_AdmissionControllerConfig_Enabled, DynamicConfig_AdmissionControllerConfig_TimeoutSeconds = EXCLUDED.DynamicConfig_AdmissionControllerConfig_TimeoutSeconds, DynamicConfig_AdmissionControllerConfig_ScanInline = EXCLUDED.DynamicConfig_AdmissionControllerConfig_ScanInline, DynamicConfig_AdmissionControllerConfig_DisableBypass = EXCLUDED.DynamicConfig_AdmissionControllerConfig_DisableBypass, DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates = EXCLUDED.DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates, DynamicConfig_RegistryOverride = EXCLUDED.DynamicConfig_RegistryOverride, DynamicConfig_DisableAuditLogs = EXCLUDED.DynamicConfig_DisableAuditLogs, TolerationsConfig_Disabled = EXCLUDED.TolerationsConfig_Disabled, Priority = EXCLUDED.Priority, HealthStatus_Id = EXCLUDED.HealthStatus_Id, HealthStatus_CollectorHealthInfo_Version = EXCLUDED.HealthStatus_CollectorHealthInfo_Version, HealthStatus_CollectorHealthInfo_TotalDesiredPods = EXCLUDED.HealthStatus_CollectorHealthInfo_TotalDesiredPods, HealthStatus_CollectorHealthInfo_TotalReadyPods = EXCLUDED.HealthStatus_CollectorHealthInfo_TotalReadyPods, HealthStatus_CollectorHealthInfo_TotalRegisteredNodes = EXCLUDED.HealthStatus_CollectorHealthInfo_TotalRegisteredNodes, HealthStatus_CollectorHealthInfo_StatusErrors = EXCLUDED.HealthStatus_CollectorHealthInfo_StatusErrors, HealthStatus_AdmissionControlHealthInfo_TotalDesiredPods = EXCLUDED.HealthStatus_AdmissionControlHealthInfo_TotalDesiredPods, HealthStatus_AdmissionControlHealthInfo_TotalReadyPods = EXCLUDED.HealthStatus_AdmissionControlHealthInfo_TotalReadyPods, HealthStatus_AdmissionControlHealthInfo_StatusErrors = EXCLUDED.HealthStatus_AdmissionControlHealthInfo_StatusErrors, HealthStatus_SensorHealthStatus = EXCLUDED.HealthStatus_SensorHealthStatus, HealthStatus_CollectorHealthStatus = EXCLUDED.HealthStatus_CollectorHealthStatus, HealthStatus_OverallHealthStatus = EXCLUDED.HealthStatus_OverallHealthStatus, HealthStatus_AdmissionControlHealthStatus = EXCLUDED.HealthStatus_AdmissionControlHealthStatus, HealthStatus_LastContact = EXCLUDED.HealthStatus_LastContact, HealthStatus_HealthInfoComplete = EXCLUDED.HealthStatus_HealthInfoComplete, SlimCollector = EXCLUDED.SlimCollector, HelmConfig_DynamicConfig_AdmissionControllerConfig_Enabled = EXCLUDED.HelmConfig_DynamicConfig_AdmissionControllerConfig_Enabled, HelmConfig_DynamicConfig_AdmissionControllerConfig_TimeoutSeconds = EXCLUDED.HelmConfig_DynamicConfig_AdmissionControllerConfig_TimeoutSeconds, HelmConfig_DynamicConfig_AdmissionControllerConfig_ScanInline = EXCLUDED.HelmConfig_DynamicConfig_AdmissionControllerConfig_ScanInline, HelmConfig_DynamicConfig_AdmissionControllerConfig_DisableBypass = EXCLUDED.HelmConfig_DynamicConfig_AdmissionControllerConfig_DisableBypass, HelmConfig_DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates = EXCLUDED.HelmConfig_DynamicConfig_AdmissionControllerConfig_EnforceOnUpdates, HelmConfig_DynamicConfig_RegistryOverride = EXCLUDED.HelmConfig_DynamicConfig_RegistryOverride, HelmConfig_DynamicConfig_DisableAuditLogs = EXCLUDED.HelmConfig_DynamicConfig_DisableAuditLogs, HelmConfig_StaticConfig_Type = EXCLUDED.HelmConfig_StaticConfig_Type, HelmConfig_StaticConfig_MainImage = EXCLUDED.HelmConfig_StaticConfig_MainImage, HelmConfig_StaticConfig_CentralApiEndpoint = EXCLUDED.HelmConfig_StaticConfig_CentralApiEndpoint, HelmConfig_StaticConfig_CollectionMethod = EXCLUDED.HelmConfig_StaticConfig_CollectionMethod, HelmConfig_StaticConfig_CollectorImage = EXCLUDED.HelmConfig_StaticConfig_CollectorImage, HelmConfig_StaticConfig_AdmissionController = EXCLUDED.HelmConfig_StaticConfig_AdmissionController, HelmConfig_StaticConfig_AdmissionControllerUpdates = EXCLUDED.HelmConfig_StaticConfig_AdmissionControllerUpdates, HelmConfig_StaticConfig_TolerationsConfig_Disabled = EXCLUDED.HelmConfig_StaticConfig_TolerationsConfig_Disabled, HelmConfig_StaticConfig_SlimCollector = EXCLUDED.HelmConfig_StaticConfig_SlimCollector, HelmConfig_StaticConfig_AdmissionControllerEvents = EXCLUDED.HelmConfig_StaticConfig_AdmissionControllerEvents, HelmConfig_ConfigFingerprint = EXCLUDED.HelmConfig_ConfigFingerprint, HelmConfig_ClusterLabels = EXCLUDED.HelmConfig_ClusterLabels, MostRecentSensorId_SystemNamespaceId = EXCLUDED.MostRecentSensorId_SystemNamespaceId, MostRecentSensorId_DefaultNamespaceId = EXCLUDED.MostRecentSensorId_DefaultNamespaceId, MostRecentSensorId_AppNamespace = EXCLUDED.MostRecentSensorId_AppNamespace, MostRecentSensorId_AppNamespaceId = EXCLUDED.MostRecentSensorId_AppNamespaceId, MostRecentSensorId_AppServiceaccountId = EXCLUDED.MostRecentSensorId_AppServiceaccountId, MostRecentSensorId_K8SNodeName = EXCLUDED.MostRecentSensorId_K8SNodeName, AuditLogState = EXCLUDED.AuditLogState, InitBundleId = EXCLUDED.InitBundleId, ManagedBy = EXCLUDED.ManagedBy, serialized = EXCLUDED.serialized"
	_, err := tx.Exec(ctx, finalStr, values...)
	if err != nil {
		return err
	}

	return nil
}

// New returns a new Store instance using the provided sql instance.
func New(ctx context.Context, db *pgxpool.Pool) Store {
	createTableClusters(ctx, db)

	return &storeImpl{
		db: db,
	}
}

func (s *storeImpl) upsert(ctx context.Context, objs ...*storage.Cluster) error {
	conn, release := s.acquireConn(ctx, ops.Get, "Cluster")
	defer release()

	for _, obj := range objs {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}

		if err := insertIntoClusters(ctx, tx, obj); err != nil {
			if err := tx.Rollback(ctx); err != nil {
				return err
			}
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *storeImpl) Upsert(ctx context.Context, obj *storage.Cluster) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Upsert, "Cluster")

	return s.upsert(ctx, obj)
}

func (s *storeImpl) UpsertMany(ctx context.Context, objs []*storage.Cluster) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.UpdateMany, "Cluster")

	return s.upsert(ctx, objs...)
}

// Count returns the number of objects in the store
func (s *storeImpl) Count(ctx context.Context) (int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Count, "Cluster")

	row := s.db.QueryRow(ctx, countStmt)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Exists returns if the id exists in the store
func (s *storeImpl) Exists(ctx context.Context, id string, healthStatusId string) (bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Exists, "Cluster")

	row := s.db.QueryRow(ctx, existsStmt, id, healthStatusId)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, pgutils.ErrNilIfNoRows(err)
	}
	return exists, nil
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(ctx context.Context, id string, healthStatusId string) (*storage.Cluster, bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Get, "Cluster")

	conn, release := s.acquireConn(ctx, ops.Get, "Cluster")
	defer release()

	row := conn.QueryRow(ctx, getStmt, id, healthStatusId)
	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, false, pgutils.ErrNilIfNoRows(err)
	}

	var msg storage.Cluster
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, false, err
	}
	return &msg, true, nil
}

func (s *storeImpl) acquireConn(ctx context.Context, op ops.Op, typ string) (*pgxpool.Conn, func()) {
	defer metrics.SetAcquireDBConnDuration(time.Now(), op, typ)
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		panic(err)
	}
	return conn, conn.Release
}

// Delete removes the specified ID from the store
func (s *storeImpl) Delete(ctx context.Context, id string, healthStatusId string) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Remove, "Cluster")

	conn, release := s.acquireConn(ctx, ops.Remove, "Cluster")
	defer release()

	if _, err := conn.Exec(ctx, deleteStmt, id, healthStatusId); err != nil {
		return err
	}
	return nil
}

// Walk iterates over all of the objects in the store and applies the closure
func (s *storeImpl) Walk(ctx context.Context, fn func(obj *storage.Cluster) error) error {
	rows, err := s.db.Query(ctx, walkStmt)
	if err != nil {
		return pgutils.ErrNilIfNoRows(err)
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var msg storage.Cluster
		if err := proto.Unmarshal(data, &msg); err != nil {
			return err
		}
		if err := fn(&msg); err != nil {
			return err
		}
	}
	return nil
}

//// Used for testing

func dropTableClusters(ctx context.Context, db *pgxpool.Pool) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS clusters CASCADE")

}

func Destroy(ctx context.Context, db *pgxpool.Pool) {
	dropTableClusters(ctx, db)
}

//// Stubs for satisfying legacy interfaces

// AckKeysIndexed acknowledges the passed keys were indexed
func (s *storeImpl) AckKeysIndexed(ctx context.Context, keys ...string) error {
	return nil
}

// GetKeysToIndex returns the keys that need to be indexed
func (s *storeImpl) GetKeysToIndex(ctx context.Context) ([]string, error) {
	return nil, nil
}
