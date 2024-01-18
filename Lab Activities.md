🟢TASK🟢 **List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)**  

First I did a quick search and found out that the only index available was "botsv3"
```
index=* | stats count by index
```
Then I went to investigate where AWS stores logs for user access and got to: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-logging-and-monitoring.html, AWS CloudTrail made the most sense based on the descriptions: ..."captures all API calls for IAM and AWS STS as events, including calls from the console and API calls"...
```
index=botsv3 | stats count by sourcetype
```
Sourcetype "aws:cloudtrail" identified

The next step for me was to find out what exact data is stored in CludTrial:
```
index=botsv3 sourcetype=aws:cloudtrail | fieldsummary
```
<details>
  <summary>List of all the fields in CloudTrial</summary>
AssumeRole
AuthorizeSecurityGroupIngress
ConsoleLogin
CreateAccessKey
CreateDefaultVpc
CreateLogStream
CreateTags
CreateUser
Decrypt
DeleteAccessKey
DeleteAlarms
DeregisterTargets
DescribeAccountAttributes
DescribeAddresses
DescribeAlarms
DescribeAutoScalingGroups
DescribeAvailabilityZones
DescribeClusterParameterGroups
DescribeClusterSecurityGroups
DescribeClusterSnapshots
DescribeClusterSubnetGroups
DescribeClusters
DescribeConfigRuleEvaluationStatus
DescribeConfigRules
DescribeDBInstances
DescribeDBSecurityGroups
DescribeDBSnapshotAttributes
DescribeDBSnapshots
DescribeDBSubnetGroups
DescribeEventSubscriptions
DescribeHosts
DescribeIdFormat
DescribeImages
DescribeInstanceAttribute
DescribeInstanceCreditSpecifications
DescribeInstanceStatus
DescribeInstances
DescribeKeyPairs
DescribeLaunchConfigurations
DescribeLaunchTemplateVersions
DescribeLaunchTemplates
DescribeLifecycleHooks
DescribeListeners
DescribeLoadBalancerAttributes
DescribeLoadBalancers
DescribeNetworkAcls
DescribeNetworkInterfaces
DescribePlacementGroups
DescribePolicies
DescribeReservedInstances
DescribeRouteTables
DescribeScalingActivities
DescribeSecurityGroups
DescribeSnapshots
DescribeStaleSecurityGroups
DescribeSubnets
DescribeTags
DescribeTargetGroupAttributes
DescribeTargetGroups
DescribeTargetHealth
DescribeTrails
DescribeVolumeStatus
DescribeVolumes
DescribeVolumesModifications
DescribeVpcs
GetAccountPasswordPolicy
GetAccountSummary
GetBucketAcl
GetBucketCors
GetBucketEncryption
GetBucketLifecycle
GetBucketLocation
GetBucketLogging
GetBucketNotification
GetBucketPolicy
GetBucketReplication
GetBucketRequestPayment
GetBucketTagging
GetBucketVersioning
GetBucketWebsite
GetCallerIdentity
GetComplianceDetailsByConfigRule
GetComplianceSummaryByConfigRule
GetConsoleOutput
GetConsoleScreenshot
GetSessionToken
GetUser
ListAccessKeys
ListAccountAliases
ListAssessmentRuns
ListAttachedUserPolicies
ListBuckets
ListCertificates
ListDistributions
ListFindings
ListFunctions20150331
ListGroups
ListInstanceProfiles
ListSSHPublicKeys
ListServiceSpecificCredentials
ListTagsForResource
ListUsers
PutBucketAcl
PutEvaluations
PutMetricAlarm
PutScalingPolicy
RegisterTargets
RevokeSecurityGroupIngress
RunInstances
StartAssessmentRun
TerminateInstances
UpdateAccessKey
UpdateSecurityGroupRuleDescriptionsIngress
</details>
Found "userIdentity.userName" which is the most aligned to what I was looking for to answer the question.
Finally enumerated the available user names:
```
index=botsv3 sourcetype=aws:cloudtrail | stats count by userIdentity.userName
```
**Answer**: bstoll,btun,splunk_access,web_admin

🟢TASK🟢 **What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)**  

Online search took me to https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html where I found:
```
...
"userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAIDPPEZS35WEXAMPLE:AssumedRoleSessionName",
    "arn": "arn:aws:sts::123456789012:assumed-role/RoleToBeAssumed/MySessionName",
    "accountId": "123456789012",
    "accessKeyId": "",
    "sessionContext": {
      "attributes": {
        "mfaAuthenticated": "false",
        "creationDate": "20131102T010628Z"
      },
      "sessionIssuer": {
        "type": "Role",
        "principalId": "AROAIDPPEZS35WEXAMPLE",
        "arn": "arn:aws:iam::123456789012:role/RoleToBeAssumed",
        "accountId": "123456789012",
        "userName": "RoleToBeAssumed"
      }
    }
}
...
```
The following search then brings four events
```
index=botsv3 sourcetype=aws:cloudtrail 
| search userIdentity.sessionContext.mfaAuthenticated=false
```
**Answer**: userIdentity.sessionContext.mfaAuthenticated

🟢TASK🟢 **What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)**  

Again had to check if there's any sourcetype that points to hardware-related logs
```
index=botsv3 | stats count by sourcetype
```
I found the sourcetype: "hardware" and its results all bring the same processor info
```
index=botsv3 sourcetype=hardware
```
**Answer**: E5-2676
