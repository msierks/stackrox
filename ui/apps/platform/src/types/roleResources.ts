// central/role/resources/list.go

export type ResourceName =
    | 'Access'
    | 'Administration'
    | 'APIToken'
    | 'Alert'
    | 'AllComments'
    | 'AuthPlugin'
    | 'AuthProvider'
    | 'BackupPlugins'
    | 'CVE'
    | 'Cluster'
    | 'Compliance'
    | 'ComplianceRunSchedule'
    | 'ComplianceRuns'
    | 'Config'
    | 'DebugLogs'
    | 'Deployment'
    | 'DeploymentExtension'
    | 'Detection'
    | 'Group'
    | 'Image'
    | 'ImageComponent'
    | 'ImageIntegration'
    | 'Indicator'
    | 'Integration'
    | 'K8sRole'
    | 'K8sRoleBinding'
    | 'K8sSubject'
    | 'Licenses'
    | 'Namespace'
    | 'NetworkBaseline'
    | 'NetworkGraph'
    | 'NetworkGraphConfig'
    | 'NetworkPolicy'
    | 'Node'
    | 'Notifier'
    | 'Policy'
    | 'ProbeUpload'
    | 'ProcessWhitelist'
    | 'Risk'
    | 'Role'
    | 'ScannerBundle'
    | 'ScannerDefinitions'
    | 'Secret'
    | 'SensorUpgradeConfig'
    | 'ServiceAccount'
    | 'ServiceIdentity'
    | 'SignatureIntegration'
    | 'User'
    | 'VulnerabilityManagementApprovals'
    | 'VulnerabilityManagementRequests'
    | 'VulnerabilityReports'
    | 'WatchedImage';
