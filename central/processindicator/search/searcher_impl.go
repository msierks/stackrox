package search

import (
	"context"

	"github.com/stackrox/rox/central/processindicator/index"
	"github.com/stackrox/rox/central/processindicator/store"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/options/processindicators"
)

var (
	indicatorSACSearchHelper = sac.ForResource(resources.Indicator).MustCreateSearchHelper(processindicators.OptionsMap)
)

// searcherImpl provides an intermediary implementation layer for ProcessStorage.
type searcherImpl struct {
	storage store.Store
	indexer index.Indexer
}

// SearchRawIndicators retrieves Policies from the indexer and storage
func (s *searcherImpl) SearchRawProcessIndicators(ctx context.Context, q *v1.Query) ([]*storage.ProcessIndicator, error) {
	results, err := s.Search(ctx, q)
	if err != nil {
		return nil, err
	}
	processes, _, err := s.storage.GetMany(search.ResultsToIDs(results))
	return processes, err
}

func (s *searcherImpl) Search(ctx context.Context, q *v1.Query) ([]search.Result, error) {
	return indicatorSACSearchHelper.Apply(s.indexer.Search)(ctx, q)
}
