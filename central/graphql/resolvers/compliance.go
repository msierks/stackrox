package resolvers

import (
	"context"
	"strings"
	"time"

	"github.com/graph-gophers/graphql-go"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/central/namespace"
	"github.com/stackrox/rox/central/node/datastore"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	pkgMetrics "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	log = logging.LoggerForModule()

	complianceOnce sync.Once
)

func init() {
	InitCompliance()
}

// InitCompliance is a function that registers compliance graphql resolvers with the static schema. It's exposed for
// feature flag / unit test reasons. Once the flag is gone, this can be folded into the normal init() method.
func InitCompliance() {
	complianceOnce.Do(func() {
		schema := getBuilder()
		utils.Must(
			schema.AddQuery("complianceStandard(id:ID!): ComplianceStandardMetadata"),
			schema.AddQuery("complianceStandards(query: String): [ComplianceStandardMetadata!]!"),
			schema.AddQuery("aggregatedResults(groupBy:[ComplianceAggregation_Scope!],unit:ComplianceAggregation_Scope!,where:String): ComplianceAggregation_Response!"),
			schema.AddQuery("complianceControl(id:ID!): ComplianceControl"),
			schema.AddQuery("complianceControlGroup(id:ID!): ComplianceControlGroup"),
			schema.AddQuery("complianceNamespaceCount(query: String): Int!"),
			schema.AddQuery("complianceClusterCount(query: String): Int!"),
			schema.AddQuery("complianceNodeCount(query: String): Int!"),
			schema.AddQuery("complianceDeploymentCount(query: String): Int!"),
			schema.AddQuery("executedControls(query: String): [ComplianceControlWithControlStatus!]!"),
			schema.AddQuery("executedControlCount(query: String): Int!"),
			schema.AddExtraResolver("ComplianceStandardMetadata", "controls: [ComplianceControl!]!"),
			schema.AddExtraResolver("ComplianceStandardMetadata", "groups: [ComplianceControlGroup!]!"),
			schema.AddUnionType("ComplianceDomainKey", []string{"ComplianceStandardMetadata", "ComplianceControlGroup", "ComplianceControl", "Cluster", "ComplianceDeployment", "Node", "Namespace"}),
			schema.AddExtraResolver("ComplianceAggregation_Result", "keys: [ComplianceDomainKey!]!"),
			schema.AddUnionType("Resource", []string{"ComplianceDeployment", "Cluster", "Node"}),
			schema.AddType("ControlResult", []string{"resource: Resource", "control: ComplianceControl", "value: ComplianceResultValue"}),
			schema.AddExtraResolver("ComplianceStandardMetadata", "complianceResults(query: String): [ControlResult!]!"),
			schema.AddExtraResolver("ComplianceControl", "complianceResults(query: String): [ControlResult!]!"),
			schema.AddExtraResolver("ComplianceControl", "complianceControlEntities(clusterID: ID!): [Node!]!"),
			schema.AddType("ComplianceControlNodeCount", []string{"failingCount: Int!", "passingCount: Int!", "unknownCount: Int!"}),
			schema.AddType("ComplianceControlWithControlStatus", []string{"complianceControl: ComplianceControl!", "controlStatus: String!"}),
			schema.AddExtraResolver("ComplianceControl", "complianceControlNodeCount(query: String): ComplianceControlNodeCount"),
			schema.AddExtraResolver("ComplianceControl", "complianceControlNodes(query: String): [Node!]!"),
			schema.AddExtraResolver("ComplianceControl", "complianceControlFailingNodes(query: String): [Node!]!"),
			schema.AddExtraResolver("ComplianceControl", "complianceControlPassingNodes(query: String): [Node!]!"),
		)
	})
}

// ComplianceStandards returns graphql resolvers for all compliance standards
func (resolver *Resolver) ComplianceStandards(ctx context.Context, query RawQuery) ([]*complianceStandardMetadataResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceStandards")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	q, err := query.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}
	results, err := resolver.ComplianceStandardStore.SearchStandards(q)
	if err != nil {
		return nil, err
	}
	var standards []*v1.ComplianceStandardMetadata
	for _, result := range results {
		standard, ok, err := resolver.ComplianceStandardStore.Standard(result.ID)
		if !ok || err != nil {
			continue
		}
		standards = append(standards, standard.GetMetadata())
	}
	return resolver.wrapComplianceStandardMetadatas(standards, nil)
}

// ComplianceStandard returns a graphql resolver for a named compliance standard
func (resolver *Resolver) ComplianceStandard(ctx context.Context, args struct{ graphql.ID }) (*complianceStandardMetadataResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceStandard")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	return resolver.wrapComplianceStandardMetadata(
		resolver.ComplianceStandardStore.StandardMetadata(string(args.ID)))
}

// ComplianceControl retrieves an individual control by ID
func (resolver *Resolver) ComplianceControl(ctx context.Context, args struct{ graphql.ID }) (*complianceControlResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceControl")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	control := resolver.ComplianceStandardStore.Control(string(args.ID))
	return resolver.wrapComplianceControl(control, control != nil, nil)
}

// ComplianceControlGroup retrieves a control group by ID
func (resolver *Resolver) ComplianceControlGroup(ctx context.Context, args struct{ graphql.ID }) (*complianceControlGroupResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceControlGroups")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	group := resolver.ComplianceStandardStore.Group(string(args.ID))
	return resolver.wrapComplianceControlGroup(group, group != nil, nil)
}

// ComplianceNamespaceCount returns count of namespaces that have compliance run on them
func (resolver *Resolver) ComplianceNamespaceCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceNamespaceCount")
	if err := readCompliance(ctx); err != nil {
		return 0, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_NAMESPACE}
	return resolver.getComplianceEntityCount(ctx, args, scope)
}

// ComplianceClusterCount returns count of clusters that have compliance run on them
func (resolver *Resolver) ComplianceClusterCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceClusterCount")
	if err := readCompliance(ctx); err != nil {
		return 0, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_CLUSTER}
	return resolver.getComplianceEntityCount(ctx, args, scope)
}

// ComplianceDeploymentCount returns count of deployments that have compliance run on them
func (resolver *Resolver) ComplianceDeploymentCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceDeploymentCount")
	if err := readCompliance(ctx); err != nil {
		return 0, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_DEPLOYMENT}
	return resolver.getComplianceEntityCount(ctx, args, scope)
}

// ComplianceNodeCount returns count of nodes that have compliance run on them
func (resolver *Resolver) ComplianceNodeCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ComplianceNodeCount")
	if err := readCompliance(ctx); err != nil {
		return 0, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_NODE}
	return resolver.getComplianceEntityCount(ctx, args, scope)
}

// ComplianceNamespaceCount returns count of namespaces that have compliance run on them
func (resolver *Resolver) getComplianceEntityCount(ctx context.Context, args RawQuery, scope []v1.ComplianceAggregation_Scope) (int32, error) {
	r, _, _, err := resolver.ComplianceAggregator.Aggregate(ctx, args.String(), scope, v1.ComplianceAggregation_CONTROL)
	if err != nil {
		return 0, err
	}
	return int32(len(r)), nil
}

// ExecutedControls returns the controls which have executed along with their status across clusters
func (resolver *Resolver) ExecutedControls(ctx context.Context, args RawQuery) ([]*ComplianceControlWithControlStatusResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ExecutedControls")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_CLUSTER, v1.ComplianceAggregation_CONTROL}
	rs, _, _, err := resolver.ComplianceAggregator.Aggregate(ctx, args.String(), scope, v1.ComplianceAggregation_CONTROL)
	if err != nil {
		return nil, err
	}
	var ret []*ComplianceControlWithControlStatusResolver
	failing := make(map[string]int32)
	passing := make(map[string]int32)
	for _, r := range rs {
		controlID, err := getScopeIDFromAggregationResult(r, v1.ComplianceAggregation_CONTROL)
		if err != nil {
			return nil, err
		}
		failing[controlID] += r.GetNumFailing()
		passing[controlID] += r.GetNumPassing()
	}
	for k := range failing {
		control := resolver.ComplianceStandardStore.Control(k)
		cc := &ComplianceControlWithControlStatusResolver{
			complianceControl: &complianceControlResolver{
				root: resolver,
				data: control,
			},
		}
		cc.controlStatus = getControlStatus(failing[k], passing[k])
		ret = append(ret, cc)
	}
	return ret, nil
}

// ExecutedControlCount returns the count of controls which have executed across all clusters
func (resolver *Resolver) ExecutedControlCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "ExecutedControls")
	if err := readCompliance(ctx); err != nil {
		return 0, err
	}
	scope := []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_CLUSTER, v1.ComplianceAggregation_CONTROL}
	rs, _, _, err := resolver.ComplianceAggregator.Aggregate(ctx, args.String(), scope, v1.ComplianceAggregation_CONTROL)
	if err != nil {
		return 0, err
	}
	controlSet := set.NewStringSet()
	for _, r := range rs {
		controlID, err := getScopeIDFromAggregationResult(r, v1.ComplianceAggregation_CONTROL)
		if err != nil {
			return 0, err
		}
		controlSet.Add(controlID)
	}
	return int32(controlSet.Cardinality()), nil
}

type aggregatedResultQuery struct {
	GroupBy *[]string
	Unit    string
	Where   *string
}

// AggregatedResults returns the aggregation of the last runs aggregated by scope, unit and filtered by a query
func (resolver *Resolver) AggregatedResults(ctx context.Context, args aggregatedResultQuery) (*complianceAggregationResponseWithDomainResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "AggregatedResults")

	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	var where string
	if args.Where != nil {
		where = *args.Where
	}

	groupBy := toComplianceAggregation_Scopes(args.GroupBy)
	unit := toComplianceAggregation_Scope(&args.Unit)

	validResults, sources, domainMap, err := resolver.ComplianceAggregator.Aggregate(ctx, where, groupBy, unit)
	if err != nil {
		return nil, err
	}

	return &complianceAggregationResponseWithDomainResolver{
		complianceAggregation_ResponseResolver: complianceAggregation_ResponseResolver{
			root: resolver,
			data: &v1.ComplianceAggregation_Response{
				Results: validResults,
				Sources: sources,
			},
		},
		domainMap: domainMap,
	}, nil
}

type complianceDomainKeyResolver struct {
	wrapped interface{}
}

func newComplianceDomainKeyResolverWrapped(ctx context.Context, root *Resolver, domain *storage.ComplianceDomain, key *v1.ComplianceAggregation_AggregationKey) interface{} {
	switch key.GetScope() {
	case v1.ComplianceAggregation_CLUSTER:
		if domain.GetCluster() != nil {
			return &clusterResolver{ctx, root, domain.GetCluster()}
		}
	case v1.ComplianceAggregation_DEPLOYMENT:
		deployment, found := domain.GetDeployments()[key.GetId()]
		if found {
			return &complianceDeploymentResolver{ctx, root, deployment}
		}
	case v1.ComplianceAggregation_NAMESPACE:
		receivedNS, found, err := namespace.ResolveByID(ctx, key.GetId(), root.NamespaceDataStore,
			root.DeploymentDataStore, root.SecretsDataStore, root.NetworkPoliciesStore)
		if err == nil && found {
			return &namespaceResolver{ctx, root, receivedNS}
		}
	case v1.ComplianceAggregation_NODE:
		node, found := domain.GetNodes()[key.GetId()]
		if found {
			return &nodeResolver{ctx, root, node}
		}
	case v1.ComplianceAggregation_STANDARD:
		standard, found, err := root.ComplianceStandardStore.StandardMetadata(key.GetId())
		if err == nil && found {
			return &complianceStandardMetadataResolver{ctx, root, standard}
		}
	case v1.ComplianceAggregation_CONTROL:
		controlID := key.GetId()
		control := root.ComplianceStandardStore.Control(controlID)
		if control != nil {
			return &complianceControlResolver{
				root: root,
				data: control,
			}
		}
	case v1.ComplianceAggregation_CATEGORY:
		groupID := key.GetId()
		control := root.ComplianceStandardStore.Group(groupID)
		if control != nil {
			return &complianceControlGroupResolver{
				root: root,
				data: control,
			}
		}
	}
	return nil
}

func (resolver *complianceDomainKeyResolver) ToCluster() (cluster *clusterResolver, found bool) {
	r, ok := resolver.wrapped.(*clusterResolver)
	return r, ok
}

func (resolver *complianceDomainKeyResolver) ToComplianceDeployment() (deployment *complianceDeploymentResolver, found bool) {
	r, ok := resolver.wrapped.(*complianceDeploymentResolver)
	return r, ok
}

func (resolver *complianceDomainKeyResolver) ToNamespace() (*namespaceResolver, bool) {
	r, ok := resolver.wrapped.(*namespaceResolver)
	return r, ok
}

func (resolver *complianceDomainKeyResolver) ToNode() (node *nodeResolver, found bool) {
	r, ok := resolver.wrapped.(*nodeResolver)
	return r, ok
}

func (resolver *complianceDomainKeyResolver) ToComplianceStandardMetadata() (standard *complianceStandardMetadataResolver, found bool) {
	r, ok := resolver.wrapped.(*complianceStandardMetadataResolver)
	return r, ok
}

// ToComplianceControl returns a resolver for a control if the domain key refers to a control and it exists
func (resolver *complianceDomainKeyResolver) ToComplianceControl() (control *complianceControlResolver, found bool) {
	r, ok := resolver.wrapped.(*complianceControlResolver)
	return r, ok
}

// ToComplianceControlGroup returns a resolver for a group if the domain key refers to a control group and it exists
func (resolver *complianceDomainKeyResolver) ToComplianceControlGroup() (group *complianceControlGroupResolver, found bool) {
	r, ok := resolver.wrapped.(*complianceControlGroupResolver)
	return r, ok
}

// ComplianceDomain returns a graphql resolver that loads the underlying object for an aggregation key
func (resolver *complianceAggregationResultWithDomainResolver) Keys(ctx context.Context) ([]*complianceDomainKeyResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Compliance, "Keys")

	output := make([]*complianceDomainKeyResolver, len(resolver.data.AggregationKeys))
	for i, v := range resolver.data.AggregationKeys {
		wrapped := newComplianceDomainKeyResolverWrapped(ctx, resolver.root, resolver.domain, v)
		output[i] = &complianceDomainKeyResolver{
			wrapped: wrapped,
		}
	}
	return output, nil
}

// ComplianceResults returns graphql resolvers for all matching compliance results
func (resolver *Resolver) ComplianceResults(ctx context.Context, query RawQuery) ([]*complianceControlResultResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Compliance, "ComplianceResults")

	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	q, err := query.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}
	return resolver.wrapComplianceControlResults(
		resolver.ComplianceDataStore.QueryControlResults(ctx, q))
}

func (resolver *complianceStandardMetadataResolver) Controls(ctx context.Context) ([]*complianceControlResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	return resolver.root.wrapComplianceControls(
		resolver.root.ComplianceStandardStore.Controls(resolver.data.GetId()))
}

func (resolver *complianceStandardMetadataResolver) Groups(ctx context.Context) ([]*complianceControlGroupResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	return resolver.root.wrapComplianceControlGroups(
		resolver.root.ComplianceStandardStore.Groups(resolver.data.GetId()))
}

type controlResultResolver struct {
	root       *Resolver
	controlID  string
	value      *storage.ComplianceResultValue
	deployment *storage.ComplianceDeployment
	cluster    *storage.Cluster
	node       *storage.Node
}

type bulkControlResults []*controlResultResolver

func newBulkControlResults() *bulkControlResults {
	output := make(bulkControlResults, 0)
	return &output
}

func (container *bulkControlResults) addComplianceDeploymentData(root *Resolver, results []*storage.ComplianceRunResults, filter func(*storage.ComplianceDeployment, *v1.ComplianceControl) bool) {
	for _, runResult := range results {
		for did, res := range runResult.GetDeploymentResults() {
			deployment := runResult.GetDomain().GetDeployments()[did]
			results := res.GetControlResults()
			for controlID, result := range results {
				if filter == nil || filter(deployment, root.ComplianceStandardStore.Control(controlID)) {
					*container = append(*container, &controlResultResolver{
						root:       root,
						controlID:  controlID,
						value:      result,
						deployment: deployment,
					})
				}
			}
		}
	}
}

func (container *bulkControlResults) addClusterData(root *Resolver, results []*storage.ComplianceRunResults, filter func(control *v1.ComplianceControl) bool) {
	for _, runResult := range results {
		res := runResult.GetClusterResults()
		results := res.GetControlResults()
		for controlID, result := range results {
			if filter == nil || filter(root.ComplianceStandardStore.Control(controlID)) {
				*container = append(*container, &controlResultResolver{
					root:      root,
					controlID: controlID,
					value:     result,
					cluster:   runResult.GetDomain().GetCluster(),
				})
			}
		}
	}
}

func (container *bulkControlResults) addNodeData(root *Resolver, results []*storage.ComplianceRunResults, filter func(node *storage.Node, control *v1.ComplianceControl) bool) {
	for _, runResult := range results {
		for nodeID, res := range runResult.GetNodeResults() {
			node := runResult.GetDomain().GetNodes()[nodeID]
			results := res.GetControlResults()
			for controlID, result := range results {
				if filter == nil || filter(node, root.ComplianceStandardStore.Control(controlID)) {
					*container = append(*container, &controlResultResolver{
						root:      root,
						controlID: controlID,
						value:     result,
						node:      node,
					})
				}
			}
		}
	}
}

func (resolver *controlResultResolver) Resource(ctx context.Context) *controlResultResolver {
	return resolver
}

func (resolver *controlResultResolver) Control(ctx context.Context) (*complianceControlResolver, error) {
	return resolver.root.ComplianceControl(ctx, struct{ graphql.ID }{graphql.ID(resolver.controlID)})
}

func (resolver *controlResultResolver) ToComplianceDeployment() (*complianceDeploymentResolver, bool) {
	if resolver.deployment == nil {
		return nil, false
	}
	return &complianceDeploymentResolver{nil, resolver.root, resolver.deployment}, true
}

func (resolver *controlResultResolver) ToCluster() (*clusterResolver, bool) {
	if resolver.cluster == nil {
		return nil, false
	}
	return &clusterResolver{root: resolver.root, data: resolver.cluster}, true
}

func (resolver *controlResultResolver) ToNode() (*nodeResolver, bool) {
	if resolver.node == nil {
		return nil, false
	}
	return &nodeResolver{root: resolver.root, data: resolver.node}, true
}

func (resolver *controlResultResolver) Value(ctx context.Context) *complianceResultValueResolver {
	return &complianceResultValueResolver{
		root: resolver.root,
		data: resolver.value,
	}
}

func (resolver *complianceStandardMetadataResolver) ComplianceResults(ctx context.Context, args RawQuery) ([]*controlResultResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Compliance, "ComplianceResults")

	if err := readCompliance(ctx); err != nil {
		return nil, err
	}

	runResults, err := resolver.root.ComplianceAggregator.GetResultsWithEvidence(ctx, args.String())
	if err != nil {
		return nil, err
	}
	output := newBulkControlResults()
	output.addClusterData(resolver.root, runResults, nil)
	output.addComplianceDeploymentData(resolver.root, runResults, nil)
	output.addNodeData(resolver.root, runResults, nil)

	return *output, nil
}

func (resolver *complianceControlResolver) ComplianceResults(ctx context.Context, args RawQuery) ([]*controlResultResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	runResults, err := resolver.root.ComplianceAggregator.GetResultsWithEvidence(ctx, args.String())
	if err != nil {
		return nil, err
	}
	output := newBulkControlResults()
	output.addClusterData(resolver.root, runResults, func(control *v1.ComplianceControl) bool {
		return control.GetId() == resolver.data.GetId()
	})
	output.addComplianceDeploymentData(resolver.root, runResults, func(deployment *storage.ComplianceDeployment, control *v1.ComplianceControl) bool {
		return control.GetId() == resolver.data.GetId()
	})
	output.addNodeData(resolver.root, runResults, func(node *storage.Node, control *v1.ComplianceControl) bool {
		return control.GetId() == resolver.data.GetId()
	})

	return *output, nil
}

func (resolver *complianceControlResolver) ComplianceControlEntities(ctx context.Context, args struct{ ClusterID graphql.ID }) ([]*nodeResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	clusterID := string(args.ClusterID)
	standardIDs, err := getStandardIDs(ctx, resolver.root.ComplianceStandardStore)
	if err != nil {
		return nil, err
	}
	hasComplianceSuccessfullyRun, err := resolver.root.ComplianceDataStore.IsComplianceRunSuccessfulOnCluster(ctx, clusterID, standardIDs)
	if err != nil || !hasComplianceSuccessfullyRun {
		return nil, err
	}
	store, err := resolver.root.NodeGlobalDataStore.GetClusterNodeStore(ctx, clusterID, false)
	if err != nil {
		return nil, err
	}
	return resolver.root.wrapNodes(store.ListNodes())
}

func (resolver *complianceControlResolver) ComplianceControlNodeCount(ctx context.Context, args RawQuery) (*complianceControlNodeCountResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	nr := complianceControlNodeCountResolver{failingCount: 0, passingCount: 0, unknownCount: 0}
	standardIDs, err := getStandardIDs(ctx, resolver.root.ComplianceStandardStore)
	if err != nil {
		return nil, err
	}
	clusterIDs, err := resolver.getClusterIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, clusterID := range clusterIDs {
		rs, ok, err := resolver.getNodeControlAggregationResults(ctx, clusterID, standardIDs, args)
		if !ok || err != nil {
			return nil, err
		}
		ret := getComplianceControlNodeCountFromAggregationResults(rs)
		nr.failingCount += ret.FailingCount()
		nr.passingCount += ret.PassingCount()
		nr.unknownCount += ret.UnknownCount()
	}
	return &nr, nil
}

func (resolver *complianceControlResolver) ComplianceControlNodes(ctx context.Context, args RawQuery) ([]*nodeResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	var ret []*nodeResolver
	standardIDs, err := getStandardIDs(ctx, resolver.root.ComplianceStandardStore)
	if err != nil {
		return nil, err
	}
	clusterIDs, err := resolver.getClusterIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, clusterID := range clusterIDs {
		rs, ok, err := resolver.getNodeControlAggregationResults(ctx, clusterID, standardIDs, args)
		if !ok || err != nil {
			return nil, err
		}
		ds, err := resolver.root.NodeGlobalDataStore.GetClusterNodeStore(ctx, clusterID, false)
		if err != nil {
			return nil, err
		}
		resolvers, err := resolver.root.wrapNodes(getResultNodesFromAggregationResults(rs, any, ds))
		if err != nil {
			return nil, err
		}
		ret = append(ret, resolvers...)
	}
	return ret, nil
}

func (resolver *complianceControlResolver) ComplianceControlFailingNodes(ctx context.Context, args RawQuery) ([]*nodeResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	var ret []*nodeResolver
	standardIDs, err := getStandardIDs(ctx, resolver.root.ComplianceStandardStore)
	if err != nil {
		return nil, err
	}
	clusterIDs, err := resolver.getClusterIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, clusterID := range clusterIDs {
		rs, ok, err := resolver.getNodeControlAggregationResults(ctx, clusterID, standardIDs, args)
		if !ok || err != nil {
			return nil, err
		}
		ds, err := resolver.root.NodeGlobalDataStore.GetClusterNodeStore(ctx, clusterID, false)
		if err != nil {
			return nil, err
		}
		resolvers, err := resolver.root.wrapNodes(getResultNodesFromAggregationResults(rs, failing, ds))
		if err != nil {
			return nil, err
		}
		ret = append(ret, resolvers...)
	}
	return ret, nil
}

func (resolver *complianceControlResolver) ComplianceControlPassingNodes(ctx context.Context, args RawQuery) ([]*nodeResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}
	standardIDs, err := getStandardIDs(ctx, resolver.root.ComplianceStandardStore)
	if err != nil {
		return nil, err
	}
	var ret []*nodeResolver
	clusterIDs, err := resolver.getClusterIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, clusterID := range clusterIDs {
		rs, ok, err := resolver.getNodeControlAggregationResults(ctx, clusterID, standardIDs, args)
		if !ok || err != nil {
			return nil, err
		}
		ds, err := resolver.root.NodeGlobalDataStore.GetClusterNodeStore(ctx, clusterID, false)
		if err != nil {
			return nil, err
		}
		resolvers, err := resolver.root.wrapNodes(getResultNodesFromAggregationResults(rs, passing, ds))
		if err != nil {
			return nil, err
		}
		ret = append(ret, resolvers...)
	}
	return ret, nil
}

func (resolver *complianceControlResolver) getNodeControlAggregationResults(ctx context.Context, clusterID string, standardIDs []string, args RawQuery) ([]*v1.ComplianceAggregation_Result, bool, error) {
	hasComplianceSuccessfullyRun, err := resolver.root.ComplianceDataStore.IsComplianceRunSuccessfulOnCluster(ctx, clusterID, standardIDs)
	if err != nil || !hasComplianceSuccessfullyRun {
		return nil, false, err
	}
	query, err := search.NewQueryBuilder().AddExactMatches(search.ClusterID, clusterID).
		AddExactMatches(search.ControlID, resolver.data.GetId()).RawQuery()
	if err != nil {
		return nil, false, err
	}
	if args.Query != nil {
		query = strings.Join([]string{query, *(args.Query)}, "+")
	}
	rs, _, _, err := resolver.root.ComplianceAggregator.Aggregate(ctx, query, []v1.ComplianceAggregation_Scope{v1.ComplianceAggregation_CONTROL, v1.ComplianceAggregation_NODE}, v1.ComplianceAggregation_NODE)
	if err != nil {
		return nil, false, err
	}
	return rs, true, nil
}

func getResultNodesFromAggregationResults(results []*v1.ComplianceAggregation_Result, nodeType resultType, ds datastore.DataStore) ([]*storage.Node, error) {
	if ds == nil {
		return nil, errors.Wrap(errors.New("empty node datastore encountered"), "argument ds is nil")
	}
	var nodes []*storage.Node
	for _, r := range results {
		if (nodeType == passing && r.GetNumPassing() == 0) || (nodeType == failing && r.GetNumFailing() == 0) {
			continue
		}
		nodeID, err := getScopeIDFromAggregationResult(r, v1.ComplianceAggregation_NODE)
		if err != nil {
			continue
		}
		node, err := ds.GetNode(nodeID)
		if err != nil {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

type resultType int

const (
	failing resultType = iota
	passing
	any
)

func getScopeIDFromAggregationResult(result *v1.ComplianceAggregation_Result, scope v1.ComplianceAggregation_Scope) (string, error) {
	if result == nil {
		return "", errors.New("empty aggregation result encountered: compliance aggregation result is nil")
	}
	for _, k := range result.GetAggregationKeys() {
		if k.Scope == scope {
			return k.GetId(), nil
		}
	}
	return "", errors.New("bad arguments: scope was not one of the aggregation keys")
}

type complianceControlNodeCountResolver struct {
	failingCount int32
	passingCount int32
	unknownCount int32
}

func (resolver *complianceControlNodeCountResolver) FailingCount() int32 {
	return resolver.failingCount
}

func (resolver *complianceControlNodeCountResolver) PassingCount() int32 {
	return resolver.passingCount
}

func (resolver *complianceControlNodeCountResolver) UnknownCount() int32 {
	return resolver.unknownCount
}

// ComplianceControlWithControlStatusResolver represents a control with its status across clusters
type ComplianceControlWithControlStatusResolver struct {
	complianceControl *complianceControlResolver
	controlStatus     string
}

// ComplianceControl returns a control of ComplianceControlWithControlStatusResolver
func (c *ComplianceControlWithControlStatusResolver) ComplianceControl() *complianceControlResolver {
	if c == nil {
		return nil
	}
	return c.complianceControl
}

// ControlStatus returns a control status of ComplianceControlWithControlStatusResolver
func (c *ComplianceControlWithControlStatusResolver) ControlStatus() string {
	if c == nil {
		return ""
	}
	return c.controlStatus
}
