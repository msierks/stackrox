import React, { useEffect, useState } from 'react';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import isEqual from 'lodash/isEqual';

import { selectors } from 'reducers';
import { actions as pageActions } from 'reducers/network/page';
import { actions as searchActions } from 'reducers/network/search';
import useURLSearch from 'hooks/useURLSearch';
import searchOptionsToQuery from 'services/searchOptionsToQuery';
import { getSearchOptionsForCategory } from 'services/SearchService';
import { isCompleteSearchFilter } from 'utils/searchUtils';
import SearchFilterInput from 'Components/SearchFilterInput';
import {
    ORCHESTRATOR_COMPONENT_KEY,
    orchestratorComponentOption,
} from 'Containers/Navigation/OrchestratorComponentsToggle';

import './NetworkSearch.css';

function searchFilterToSearchEntries(searchFilter) {
    return Object.entries(searchFilter).flatMap(([key, value]) => {
        const values = Array.isArray(value) ? value : [value];
        const valueOptions = values.map((v) => ({ label: v, value: v }));
        return [{ label: `${key}:`, value: `${key}:`, type: 'categoryOption' }, ...valueOptions];
    });
}

const searchCategory = 'DEPLOYMENTS';

function NetworkSearch({
    selectedNamespaceFilters,
    dispatchSearchFilter,
    closeSidePanel,
    isDisabled,
}) {
    const [searchOptions, setSearchOptions] = useState([]);
    const { searchFilter, setSearchFilter } = useURLSearch();

    useEffect(() => {
        const { request, cancel } = getSearchOptionsForCategory(searchCategory);
        request.then(setSearchOptions).catch(() => {
            // A request error will disable the search filter.
        });

        return cancel;
    }, [setSearchOptions]);

    // Keep the Redux store in sync with the URL Search Filter
    useEffect(() => {
        dispatchSearchFilter(searchFilterToSearchEntries(searchFilter));
    }, [searchFilter, dispatchSearchFilter]);

    function onSearch(options) {
        setSearchFilter(options);
        if (isCompleteSearchFilter(options)) {
            closeSidePanel();
        }
    }

    const orchestratorComponentShowState = localStorage.getItem(ORCHESTRATOR_COMPONENT_KEY);
    const prependAutocompleteQuery =
        orchestratorComponentShowState !== 'true' ? [...orchestratorComponentOption] : [];

    if (selectedNamespaceFilters.length) {
        prependAutocompleteQuery.push({ value: 'Namespace:', type: 'categoryOption' });
        selectedNamespaceFilters.forEach((nsFilter) =>
            prependAutocompleteQuery.push({ value: nsFilter })
        );
    }

    return (
        <SearchFilterInput
            className="pf-u-w-100 network-search"
            placeholder="Add one or more deployment filters"
            searchFilter={searchFilter}
            searchCategory="DEPLOYMENTS"
            searchOptions={searchOptions}
            handleChangeSearchFilter={onSearch}
            autocompleteQueryPrefix={searchOptionsToQuery(prependAutocompleteQuery)}
            isDisabled={isDisabled}
        />
    );
}

const mapStateToProps = createStructuredSelector({
    selectedNamespaceFilters: selectors.getSelectedNamespaceFilters,
});

const mapDispatchToProps = {
    dispatchSearchFilter: searchActions.setNetworkSearchOptions,
    closeSidePanel: pageActions.closeSidePanel,
};

export default connect(mapStateToProps, mapDispatchToProps)(NetworkSearch);
