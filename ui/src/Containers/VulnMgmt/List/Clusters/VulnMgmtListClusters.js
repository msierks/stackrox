import React from 'react';
import gql from 'graphql-tag';

import queryService from 'utils/queryService';
import {
    defaultHeaderClassName,
    nonSortableHeaderClassName,
    defaultColumnClassName,
} from 'Components/Table';
import DateTimeField from 'Components/DateTimeField';
import StatusChip from 'Components/StatusChip';
import TableCountLink from 'Components/workflow/TableCountLink';
import entityTypes from 'constants/entityTypes';
import WorkflowListPage from 'Containers/Workflow/WorkflowListPage';
import CVEStackedPill from 'Components/CVEStackedPill';

import { CLUSTER_LIST_FRAGMENT } from 'Containers/VulnMgmt/VulnMgmt.fragments';
import { workflowListPropTypes, workflowListDefaultProps } from 'constants/entityPageProps';
import { clusterSortFields } from 'constants/sortFields';
import { LIST_PAGE_SIZE } from 'constants/workflowPages.constants';
import removeEntityContextColumns from 'utils/tableUtils';
import { vulMgmtPolicyQuery } from '../../Entity/VulnMgmtPolicyQueryUtil';

export const defaultClusterSort = [
    {
        id: clusterSortFields.PRIORITY,
        desc: false,
    },
];

// @TODO: remove this exception, once Clusters pagination is fixed on the back end
// eslint-disable-next-line
const VulnMgmtClusters = ({ selectedRowId, search, sort, page, data }) => {
    const query = gql`
        query getClusters(
            $query: String
            $policyQuery: String
            $scopeQuery: String
            $pagination: Pagination
        ) {
            results: clusters(query: $query, pagination: $pagination) {
                ...clusterFields
                unusedVarSink(query: $policyQuery)
                unusedVarSink(query: $scopeQuery)
            }
            count: clusterCount(query: $query)
        }
        ${CLUSTER_LIST_FRAGMENT}
    `;

    const tableSort = sort || defaultClusterSort;
    const queryOptions = {
        variables: {
            ...vulMgmtPolicyQuery,
            query: queryService.objectToWhereClause(search),
            pagination: queryService.getPagination(tableSort, page, LIST_PAGE_SIZE),
        },
    };

    function getTableColumns(workflowState) {
        const tableColumns = [
            {
                Header: 'Id',
                headerClassName: 'hidden',
                className: 'hidden',
                accessor: 'id',
            },
            {
                Header: `Cluster`,
                headerClassName: `w-1/8 ${defaultHeaderClassName}`,
                className: `w-1/8 ${defaultColumnClassName}`,
                id: clusterSortFields.CLUSTER,
                accessor: 'name',
                sortField: clusterSortFields.CLUSTER,
            },
            {
                Header: `CVEs`,
                entityType: entityTypes.CVE,
                headerClassName: `w-1/8 ${defaultHeaderClassName}`,
                className: `w-1/8 ${defaultColumnClassName}`,
                Cell: ({ original, pdf }) => {
                    const { vulnCounter, id } = original;
                    if (!vulnCounter || vulnCounter.all.total === 0) return 'No CVEs';

                    const newState = workflowState.pushListItem(id).pushList(entityTypes.CVE);
                    const url = newState.toUrl();
                    const fixableUrl = newState.setSearch({ Fixable: true }).toUrl();

                    return (
                        <CVEStackedPill
                            vulnCounter={vulnCounter}
                            url={url}
                            fixableUrl={fixableUrl}
                            hideLink={pdf}
                        />
                    );
                },
                id: clusterSortFields.CVE_COUNT,
                accessor: 'vulnCounter.all.total',
                sortField: clusterSortFields.CVE_COUNT,
            },
            {
                Header: `K8S Version`,
                headerClassName: `w-1/10 ${nonSortableHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                id: clusterSortFields.K8SVERSION,
                accessor: 'status.orchestratorMetadata.version',
                sortField: clusterSortFields.K8SVERSION,
                sortable: false,
            },
            // TODO: enable this column after data is available from the API
            // {
            //     Header: `Created`,
            //     headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            //     className: `w-1/8 ${defaultColumnClassName}`,
            //     id: clusterSortFields.CREATED,
            //     accessor: 'createdAt',
            //     sortField: clusterSortFields.CREATED
            // },
            {
                Header: `Namespaces`,
                entityType: entityTypes.NAMESPACE,
                headerClassName: `w-1/10 ${defaultHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                // eslint-disable-next-line
                Cell: ({ original, pdf }) => (
                    <TableCountLink
                        entityType={entityTypes.NAMESPACE}
                        count={original.namespaceCount}
                        textOnly={pdf}
                        selectedRowId={original.id}
                    />
                ),
                id: clusterSortFields.NAMESPACE_COUNT,
                accessor: 'namespaceCount',
                sortField: clusterSortFields.NAMESPACE_COUNT,
            },
            {
                Header: `Deployments`,
                entityType: entityTypes.DEPLOYMENT,
                headerClassName: `w-1/10 ${defaultHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                // eslint-disable-next-line
                Cell: ({ original, pdf }) => (
                    <TableCountLink
                        entityType={entityTypes.DEPLOYMENT}
                        count={original.deploymentCount}
                        textOnly={pdf}
                        selectedRowId={original.id}
                    />
                ),
                id: clusterSortFields.DEPLOYMENT_COUNT,
                accessor: 'deploymentCount',
                sortField: clusterSortFields.DEPLOYMENT_COUNT,
            },
            // @TODD, restore the Policy Counts column once its performance is improved,
            //   or remove the comment if we determine that it cannot be made performant
            //   (see https://stack-rox.atlassian.net/browse/ROX-4080)
            // {
            //     Header: `Policies`,
            //     entityType: entityTypes.POLICY,
            //     headerClassName: `w-1/10 ${nonSortableHeaderClassName}`,
            //     className: `w-1/10 ${defaultColumnClassName}`,
            //     // eslint-disable-next-line
            //     Cell: ({ original, pdf }) => (
            //         <TableCountLink
            //             entityType={entityTypes.POLICY}
            //             count={original.policyCount}
            //             textOnly={pdf}
            //             selectedRowId={original.id}
            //         />
            //     ),
            //     id: clusterSortFields.POLICY_COUNT,
            //     accessor: 'policyCount',
            //     sortField: clusterSortFields.POLICY_COUNT,
            //     sortable: false
            // },
            {
                Header: `Policy Status`,
                headerClassName: `w-1/10 ${nonSortableHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                // eslint-disable-next-line
                Cell: ({ original, pdf }) => {
                    const { policyStatus } = original;
                    const policyLabel = (
                        <StatusChip status={policyStatus && policyStatus.status} asString={pdf} />
                    );

                    return policyLabel;
                },
                id: clusterSortFields.POLICY_STATUS,
                accessor: 'policyStatus.status',
                sortField: clusterSortFields.POLICY_STATUS,
                sortable: false,
            },
            {
                Header: `Latest Violation`,
                headerClassName: `w-1/10 ${nonSortableHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                Cell: ({ original, pdf }) => {
                    const { latestViolation } = original;
                    return <DateTimeField date={latestViolation} asString={pdf} />;
                },
                id: clusterSortFields.LATEST_VIOLATION,
                accessor: 'latestViolation',
                sortField: clusterSortFields.LATEST_VIOLATION,
                sortable: false,
            },
            {
                Header: `Risk Priority`,
                headerClassName: `w-1/10 ${nonSortableHeaderClassName}`,
                className: `w-1/10 ${defaultColumnClassName}`,
                id: clusterSortFields.PRIORITY,
                accessor: 'priority',
                sortField: clusterSortFields.PRIORITY,
                sortable: true,
            },
        ];
        return removeEntityContextColumns(tableColumns, workflowState);
    }

    return (
        <WorkflowListPage
            data={data}
            query={query}
            queryOptions={queryOptions}
            entityListType={entityTypes.CLUSTER}
            getTableColumns={getTableColumns}
            selectedRowId={selectedRowId}
            search={search}
            sort={tableSort}
            page={page}
        />
    );
};

VulnMgmtClusters.propTypes = workflowListPropTypes;
VulnMgmtClusters.defaultProps = {
    ...workflowListDefaultProps,
    sort: null,
};

export default VulnMgmtClusters;
