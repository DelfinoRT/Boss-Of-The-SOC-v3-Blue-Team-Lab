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
  | First Header  | Second Header | Second Header |
| --- | --- | --- |
| AssumeRole  | AuthorizeSecurityGroupIngress  | CreateAccessKey  |
| ConsoleLogin  | CreateAccessKey  | CreateAccessKey  |
| --- | --- | --- |



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

🟢TASK🟢 **Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.**  

Did a quick search trying to find the account belonging to our guy "Bud", most probably "bstoll" or "btun"
```
index=botsv3 "bud"
```
Amongst the logs I found this:
```
 { [-]
   active: true
   alertCounts: { [+]
   }
   authType: LOCAL
   backupDeviceCount: 1
   backupUsage: [ [+]
   ]
   blocked: false
   computerCount: 1
   creationDate: 2018-08-19T13:39:48.231Z
   email: bstoll@froth.ly
   emailPromo: true
   firstName: Bud
   invited: false
   lastLoginDate: 2018-08-19T13:46:20.276Z
   lastName: Stoll
   licenses: [ [+]
   ]
   localAuthenticationOnly: false
   modificationDate: 2018-08-19T13:45:43.916Z
   modular_input_consumption_time: Mon, 20 Aug 2018 15:22:39 +0000
   notes: null
   orgId: 1852
   orgName: Frothly
   orgType: ENTERPRISE
   orgUid: 858489735492421636
   passwordReset: false
   quotaInBytes: -1
   roles: [ [+]
   ]
   securityKeyType: AccountPassword
   shareDeviceCount: 0
   status: Active
   timestamp: Mon, 20 Aug 2018 15:22:39 +0000
   userExtRef: null
   userId: 7211
   userUid: 858527737266971219
   username: bstoll@froth.ly
   usernameIsAnEmail: true
} 
```
So our guy was "bstoll" with accountId=622676721278 

The answer requires to identify a change made via API so the call should be "PUT".
After doing some googline I came across this: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html that points to
```
PutBucketPolicy
```
I did not get any results using "PutBucketPolicy"
```
index=botsv3 sourcetype=aws:cloudtrail bstoll eventName=PutBucketPolicy
```
Then I found https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html 
 2 events found querying:
```
index=botsv3 sourcetype=aws:cloudtrail bstoll eventName=PutBucketAcl
```
One of these events is granting WRITE and READ permissions to "All users"
```
 Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/global/AllUsers
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: READ
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/global/AllUsers
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: WRITE
           }
```
That's the event we are looking for, we need its EventID
**Answer**: ab45689d-69cd-41e7-8705-5350402cf7ac

🟢TASK🟢 **Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.**  

Did a quick
