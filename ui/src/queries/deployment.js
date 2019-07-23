import gql from 'graphql-tag';

export const DEPLOYMENT_QUERY = gql`
    query getDeployment($id: ID!) {
        deployment(id: $id) {
            id
            annotations {
                key
                value
            }
            clusterId
            clusterName
            hostNetwork: id
            imagePullSecrets
            inactive
            labels {
                key
                value
            }
            name
            namespace
            namespaceId
            ports {
                containerPort
                exposedPort
                exposure
                exposureInfos {
                    externalHostnames
                    externalIps
                    level
                    nodePort
                    serviceClusterIp
                    serviceId
                    serviceName
                    servicePort
                }
                name
                protocol
            }
            priority
            replicas
            serviceAccount
            serviceAccountID
            tolerations {
                key
                operator
                taintEffect
                value
            }
            type
            updatedAt
            secretCount
            imagesCount
        }
    }
`;

export const DEPLOYMENT_NAME = gql`
    query getDeployment($id: ID!) {
        result: deployment(id: $id) {
            id
            name
        }
    }
`;

export const DEPLOYMENTS_QUERY = gql`
    query getDeployments($query: String) {
        results: deployments(query: $query) {
            id
            name
            clusterName
            namespace
            deployAlertsCount
            serviceAccount
            policyStatus {
                status
                failingPolicies {
                    id
                    name
                }
            }
            secretCount
            imagesCount
        }
    }
`;

export const DEPLOYMENTS_WITH_IMAGE = gql`
    query getDeployments($query: String) {
        deployments(query: $query) {
            id
            name
            clusterName
            namespace
            serviceAccount
        }
    }
`;
