package datastore

import (
	"time"

	alertDataStore "github.com/stackrox/rox/central/alert/datastore"
	"github.com/stackrox/rox/central/cluster/index"
	"github.com/stackrox/rox/central/cluster/store"
	deploymentDataStore "github.com/stackrox/rox/central/deployment/datastore"
	nodeStore "github.com/stackrox/rox/central/node/globalstore"
	notifierProcessor "github.com/stackrox/rox/central/notifier/processor"
	secretDataStore "github.com/stackrox/rox/central/secret/datastore"
	"github.com/stackrox/rox/central/sensor/service/connection"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/search"
)

var (
	log = logging.LoggerForModule()
)

// DataStore is the entry point for modifying Cluster data.
//go:generate mockgen-wrapper DataStore
type DataStore interface {
	GetCluster(id string) (*storage.Cluster, bool, error)
	GetClusters() ([]*storage.Cluster, error)
	CountClusters() (int, error)

	AddCluster(cluster *storage.Cluster) (string, error)
	UpdateCluster(cluster *storage.Cluster) error
	RemoveCluster(id string) error
	UpdateClusterContactTime(id string, t time.Time) error
	UpdateClusterStatus(id string, status *storage.ClusterStatus) error

	Search(q *v1.Query) ([]search.Result, error)
}

// New returns an instance of DataStore.
func New(
	storage store.Store,
	indexer index.Indexer,
	ads alertDataStore.DataStore,
	dds deploymentDataStore.DataStore,
	ns nodeStore.GlobalStore,
	ss secretDataStore.DataStore,
	cm connection.Manager,
	notifier notifierProcessor.Processor) (DataStore, error) {
	ds := &datastoreImpl{
		storage:  storage,
		indexer:  indexer,
		ads:      ads,
		dds:      dds,
		ns:       ns,
		ss:       ss,
		cm:       cm,
		notifier: notifier,
	}
	if err := ds.buildIndex(); err != nil {
		return ds, err
	}
	go ds.cleanUpNodeStore()
	return ds, nil
}
