/* eslint-disable react/prop-types */
import React from 'react';
import PropTypes from 'prop-types';
import { useQuery } from 'react-apollo';

import PageNotFound from 'Components/PageNotFound';
import Loader from 'Components/Loader';
import Message from 'Components/Message';
import { useTheme } from 'Containers/ThemeProvider';
import queryService from 'utils/queryService';

import { LIST_PAGE_SIZE, defaultCountKeyMap } from 'constants/workflowPages.constants';
import useCases from 'constants/useCaseTypes';
import vulnMgmtDefaultSorts from '../VulnMgmt/VulnMgmt.defaultSorts';

export const entityGridContainerBaseClassName =
    'mx-4 grid-dense grid-auto-fit grid grid-gap-4 xl:grid-gap-6 mb-4 xxxl:grid-gap-8';

// to separate out column number related classes from the rest of the grid classes for easy column customization (see policyOverview component)
export const entityGridContainerClassName = `${entityGridContainerBaseClassName} grid-columns-1 md:grid-columns-2 lg:grid-columns-3`;

const useCaseDefaultSorts = {
    [useCases.VULN_MANAGEMENT]: vulnMgmtDefaultSorts,
};

const WorkflowEntityPage = ({
    ListComponent,
    OverviewComponent,
    entityType,
    entityId,
    entityListType,
    useCase,
    getListQuery,
    overviewQuery,
    queryOptions,
    entityContext,
    search,
    sort,
    page,
    setRefreshTrigger,
}) => {
    const { isDarkMode } = useTheme();
    const enhancedQueryOptions =
        queryOptions && queryOptions.variables ? queryOptions : { variables: {} };
    let query = overviewQuery;
    let fieldName;

    if (entityListType) {
        // sorting stuff
        const appliedSort = sort || useCaseDefaultSorts[useCase][entityListType];
        enhancedQueryOptions.variables.pagination = queryService.getPagination(
            appliedSort,
            page,
            LIST_PAGE_SIZE
        );

        const { listFieldName, fragmentName, fragment } = queryService.getFragmentInfo(
            entityType,
            entityListType,
            useCase
        );
        fieldName = listFieldName;
        query = getListQuery(listFieldName, fragmentName, fragment);
    }

    // TODO: if we are ever able to search for k8s and istio vulns, remove this hack
    if (
        enhancedQueryOptions.variables.query &&
        enhancedQueryOptions.variables.query.includes('K8S_CVE')
    ) {
        // eslint-disable-next-line no-param-reassign
        enhancedQueryOptions.variables.query = enhancedQueryOptions.variables.query.replace(
            /\+?CVE Type:K8S_CVE\+?/,
            ''
        );
    }

    const { loading, data, error } = useQuery(query, enhancedQueryOptions);
    if (loading) return <Loader />;
    if (error)
        return (
            <div className="flex items-center justify-center h-full w-full">
                <div className="m-6 w-full md:w-1/2 xl:w-3/5">
                    <Message
                        type="error"
                        message={error.message || 'An unknown error has occurred.'}
                    />
                </div>
            </div>
        );
    if (!data || !data.result) return <PageNotFound resourceType={entityType} />;
    const { result } = data;

    const listData = entityListType ? result[fieldName] : null;
    const listCountKey = defaultCountKeyMap[entityListType];
    const totalResults = result[listCountKey];
    return entityListType ? (
        <ListComponent
            entityListType={entityListType}
            totalResults={totalResults}
            data={listData}
            search={search}
            sort={sort}
            page={page}
            entityContext={{ ...entityContext, [entityType]: entityId }}
            setRefreshTrigger={setRefreshTrigger}
        />
    ) : (
        <div
            className={`w-full flex min-h-full ${
                !isDarkMode && !entityListType ? 'bg-side-panel-wave' : 'bg-base-0'
            }`}
        >
            <div className="w-full min-h-full" id="capture-widgets">
                <OverviewComponent
                    data={result}
                    entityContext={entityContext}
                    setRefreshTrigger={setRefreshTrigger}
                />
            </div>
        </div>
    );
};

WorkflowEntityPage.propTypes = {
    ListComponent: PropTypes.func.isRequired,
    OverviewComponent: PropTypes.func.isRequired,
    entityType: PropTypes.string.isRequired,
    entityId: PropTypes.string.isRequired,
    entityListType: PropTypes.string,
    useCase: PropTypes.string.isRequired,
    getListQuery: PropTypes.func.isRequired,
    overviewQuery: PropTypes.shape({}).isRequired,
    queryOptions: PropTypes.shape({}),
    entityContext: PropTypes.shape({}),
    search: PropTypes.shape({}),
    sort: PropTypes.arrayOf(PropTypes.shape({})),
    page: PropTypes.number,
    setRefreshTrigger: PropTypes.func,
};

WorkflowEntityPage.defaultProps = {
    entityListType: null,
    queryOptions: null,
    entityContext: {},
    search: null,
    sort: null,
    page: 1,
    setRefreshTrigger: null,
};

export default WorkflowEntityPage;
