import React, { useContext } from 'react';
import workflowStateContext from 'Containers/workflowStateContext';
import pluralize from 'pluralize';
import CollapsibleSection from 'Components/CollapsibleSection';
import StatusChip from 'Components/StatusChip';
import RiskScore from 'Components/RiskScore';
import Metadata from 'Components/Metadata';
import Tabs from 'Components/Tabs';
import TabContent from 'Components/TabContent';
import entityTypes from 'constants/entityTypes';
import TopRiskyEntitiesByVulnerabilities from 'Containers/VulnMgmt/widgets/TopRiskyEntitiesByVulnerabilities';
import MostRecentVulnerabilities from 'Containers/VulnMgmt/widgets/MostRecentVulnerabilities';
import TopRiskiestImagesAndComponents from 'Containers/VulnMgmt/widgets/TopRiskiestImagesAndComponents';
import DeploymentsWithMostSeverePolicyViolations from 'Containers/VulnMgmt/widgets/DeploymentsWithMostSeverePolicyViolations';
import { getPolicyTableColumns } from 'Containers/VulnMgmt/List/Policies/VulnMgmtListPolicies';
import { getCveTableColumns } from 'Containers/VulnMgmt/List/Cves/VulnMgmtListCves';

import RelatedEntitiesSideList from '../RelatedEntitiesSideList';
import TableWidget from '../TableWidget';

const VulnMgmtNamespaceOverview = ({ data }) => {
    const workflowState = useContext(workflowStateContext);

    const {
        metadata,
        policyStatus,
        policyCount,
        deploymentCount,
        imageCount,
        imageComponentCount,
        vulnCount,
        vulnerabilities
    } = data;

    const { clusterName, priority, labels } = metadata;
    const { failingPolicies, status } = policyStatus;

    const metadataKeyValuePairs = [
        {
            key: 'Cluster',
            value: clusterName
        }
    ];

    const namespaceStats = [
        <RiskScore key="risk-score" score={priority} />,
        <React.Fragment key="policy-status">
            <span className="pr-1">Policy status:</span>
            <StatusChip status={status} />
        </React.Fragment>
    ];

    function getCountData(entityType) {
        switch (entityType) {
            case entityTypes.DEPLOYMENT:
                return deploymentCount;
            case entityTypes.COMPONENT:
                return imageComponentCount;
            case entityTypes.CVE:
                return vulnCount;
            case entityTypes.IMAGE:
                return imageCount;
            case entityTypes.POLICY:
                return policyCount;
            default:
                return 0;
        }
    }

    return (
        <div className="w-full h-full" id="capture-dashboard-stretch">
            <div className="flex h-full">
                <div className="flex flex-col flex-grow">
                    <CollapsibleSection title="Namespace summary">
                        <div className="mx-4 grid grid-gap-6 xxxl:grid-gap-8 md:grid-columns-3 mb-4 pdf-page">
                            <div className="s-1">
                                <Metadata
                                    className="h-full min-w-48 bg-base-100"
                                    keyValuePairs={metadataKeyValuePairs}
                                    statTiles={namespaceStats}
                                    labels={labels}
                                    title="Details & Metadata"
                                />
                            </div>
                            <div className="sx-2 sy-1">
                                <TopRiskyEntitiesByVulnerabilities />
                            </div>
                            <div className="s-1">
                                <MostRecentVulnerabilities />
                            </div>
                            <div className="s-1">
                                <TopRiskiestImagesAndComponents />
                            </div>
                            <div className="s-1">
                                <DeploymentsWithMostSeverePolicyViolations />
                            </div>
                        </div>
                    </CollapsibleSection>
                    <CollapsibleSection title="Namespace findings">
                        <div className="flex pdf-page pdf-stretch shadow rounded relative rounded bg-base-100 mb-4 ml-4 mr-4">
                            <Tabs
                                hasTabSpacing
                                headers={[{ text: 'Policies' }, { text: 'Fixable CVEs' }]}
                            >
                                <TabContent>
                                    <TableWidget
                                        header={`${failingPolicies.length} failing ${pluralize(
                                            entityTypes.POLICY,
                                            failingPolicies.length
                                        )} across this image`}
                                        rows={failingPolicies}
                                        noDataText="No failing policies"
                                        className="bg-base-100"
                                        columns={getPolicyTableColumns(workflowState, false)}
                                        idAttribute="id"
                                    />
                                </TabContent>
                                <TabContent>
                                    <TableWidget
                                        header={`${vulnerabilities.length} fixable ${pluralize(
                                            entityTypes.CVE,
                                            vulnerabilities.length
                                        )} found across this image`}
                                        rows={vulnerabilities}
                                        entityType={entityTypes.CVE}
                                        noDataText="No fixable CVEs available in this namespace"
                                        className="bg-base-100"
                                        columns={getCveTableColumns(workflowState, false)}
                                        idAttribute="cve"
                                    />
                                </TabContent>
                            </Tabs>
                        </div>
                    </CollapsibleSection>
                </div>

                <RelatedEntitiesSideList
                    entityType={entityTypes.NAMESPACE}
                    workflowState={workflowState}
                    getCountData={getCountData}
                />
            </div>
        </div>
    );
};

export default VulnMgmtNamespaceOverview;
