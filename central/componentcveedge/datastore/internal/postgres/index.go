// Code generated by pg-bindings generator. DO NOT EDIT.
package postgres

import (
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/blevesearch"
	"github.com/stackrox/rox/pkg/search/postgres"
	"github.com/stackrox/rox/pkg/search/postgres/mapping"
)

func init() {
	mapping.RegisterCategoryToTable(v1.SearchCategory_COMPONENT_VULN_EDGE, schema)
}

// NewIndexer returns new indexer for `storage.ComponentCVEEdge`.
func NewIndexer(db *pgxpool.Pool) *indexerImpl {
	return &indexerImpl{
		db: db,
	}
}

type indexerImpl struct {
	db *pgxpool.Pool
}

func (b *indexerImpl) Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "ComponentCVEEdge")

	return postgres.RunCountRequest(v1.SearchCategory_COMPONENT_VULN_EDGE, q, b.db)
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ComponentCVEEdge")

	return postgres.RunSearchRequest(v1.SearchCategory_COMPONENT_VULN_EDGE, q, b.db)
}

//// Stubs for satisfying interfaces

func (b *indexerImpl) AddComponentCVEEdge(deployment *storage.ComponentCVEEdge) error {
	return nil
}

func (b *indexerImpl) AddComponentCVEEdges(_ []*storage.ComponentCVEEdge) error {
	return nil
}

func (b *indexerImpl) DeleteComponentCVEEdge(id string) error {
	return nil
}

func (b *indexerImpl) DeleteComponentCVEEdges(_ []string) error {
	return nil
}

func (b *indexerImpl) MarkInitialIndexingComplete() error {
	return nil
}

func (b *indexerImpl) NeedsInitialIndexing() (bool, error) {
	return false, nil
}
