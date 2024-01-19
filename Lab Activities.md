## ❓TASK❓ List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller) 

First I did a quick search and found out that the only index available was "botsv3"
```
index=* | stats count by index
```
Then I went to investigate where AWS stores logs for user access and got to: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-logging-and-monitoring.html, AWS CloudTrail made the most sense based on the descriptions: ..."captures all API calls for IAM and AWS STS as events, including calls from the console and API calls"...
```
index=botsv3 | stats count by sourcetype
```
Sourcetype "aws:cloudtrail" identified

All Source Types:
| 1  | 2 | 3 | 4  |
| --- | --- | --- | --- |
| PerfmonMk:Process | Script:GetEndpointInfo | Script:InstalledApps | Script:ListeningPorts |
| Unix:ListeningPorts | Unix:ListeningPorts | Unix:SSHDConfig | Unix:Service |
| Unix:Update | Unix:Uptime | Unix:UserAccounts | Unix:Version |
| WinHostMon | access_combined | alternatives | amazon-ssm-agent |
| amazon-ssm-agent-too_small | apache_error | aws:cloudtrail | aws:cloudwatch |
| aws:cloudwatch:guardduty | aws:cloudwatchlogs | aws:cloudwatchlogs:vpcflow | aws:config:rule |
| aws:description | aws:elb:accesslogs | aws:rds:audit | aws:rds:error |
| aws:s3:accesslogs | bandwidth | bash_history | bootstrap |
| cisco:asa | cloud-init | cloud-init-output | code42:api |
| code42:computer | code42:org | code42:security | code42:user |
| config_file | cpu | cron-too_small | dmesg |
| dpkg | error-too_small | errors | errors-too_small |
| ess_content_importer | hardware | history-2 | interfaces |
| iostat | lastlog | linux_audit | linux_secure |
| localhost-5 | lsof | maillog-too_small | ms:aad:audit |
| ms:aad:signin | ms:o365:management | ms:o365:reporting:messagetrace | o365:management:activity |
| openPorts | osquery:info | osquery:results | osquery:warning |
| out-3 | package | protocol | ps |
| stream:arp | stream:dhcp | stream:dns | stream:http |
| stream:icmp | stream:igmp | stream:ip | stream:mysql |
| stream:smb | stream:smtp | stream:tcp | stream:udp |
| symantec:ep:agent:file | symantec:ep:agt_system:file | symantec:ep:behavior:file | symantec:ep:packet:file |
| symantec:ep:risk:file | symantec:ep:scm_system:file | symantec:ep:security:file | symantec:ep:traffic:file |
| syslog | time | top | usersWithLoginPrivs |
| vmstat | who | wineventlog | xmlwineventlog |
| yum-too_small | - | - | - |

All CloudTrial events:
| 1  | 2 | 3 | 4  |
| --- | --- | --- | --- |
| AssumeRole | AuthorizeSecurityGroupIngress | CreateAccessKey | ConsoleLogin |
| CreateDefaultVpc  | CreateLogStream  | CreateTags  | CreateUser  |
| ConsoleLogin  | CreateAccessKey  | CreateAccessKey  | CreateAccessKey  |
| Decrypt  | DeleteAccessKey  | DeleteAlarms  | DeregisterTargets  |
| DescribeAccountAttributes  | DescribeAddresses  | DescribeAlarms  | DescribeAutoScalingGroups  |
| DescribeAvailabilityZones  | DescribeClusterParameterGroups  | DescribeClusterSecurityGroups  | DescribeClusterSnapshots  |
| DescribeClusterSubnetGroups  | DescribeClusters  | DescribeConfigRuleEvaluationStatus  | DescribeConfigRules  |
| DescribeDBInstances  | DescribeDBSecurityGroups  | DescribeDBSnapshotAttributes  | DescribeDBSnapshots  |
| DescribeDBSubnetGroups  | DescribeEventSubscriptions  | DescribeHosts  | DescribeIdFormat  |
| DescribeImages  | DescribeInstanceAttribute  | DescribeInstanceCreditSpecifications  | DescribeInstanceStatus  |
| DescribeInstances  | DescribeKeyPairs  | DescribeLaunchConfigurations  | DescribeLaunchTemplateVersions  |
| DescribeLaunchTemplates  | DescribeLifecycleHooks  | DescribeListeners  | DescribeLoadBalancerAttributes  |
| DescribeLoadBalancers  | DescribeNetworkAcls  | DescribeNetworkInterfaces  | DescribePlacementGroups  |
| DescribePolicies  | DescribeReservedInstances  | DescribeRouteTables  | DescribeScalingActivities  |
| DescribeSecurityGroups  | DescribeSnapshots  | DescribeStaleSecurityGroups  | DescribeSubnets  |
| DescribeTags  | DescribeTargetGroupAttributes  | DescribeTargetGroups  | DescribeTargetHealth  |
| DescribeTrails  | DescribeVolumeStatus  | DescribeVolumes  | DescribeVolumesModifications  |
| DescribeVpcs  | GetAccountPasswordPolicy  | GetAccountSummary  | GetBucketAcl  |
| GetBucketCors  | GetBucketEncryption  | GetBucketLifecycle  | GetBucketLocation  |
| GetBucketLogging  | GetBucketNotification  | GetBucketPolicy  | GetBucketReplication  |
| GetBucketRequestPayment  | GetBucketTagging  | GetBucketVersioning  | GetBucketWebsite  |
| GetCallerIdentity  | GetComplianceDetailsByConfigRule  | GetComplianceSummaryByConfigRule  | GetConsoleOutput  |
| GetConsoleScreenshot  | GetSessionToken  | GetUser  | ListAccessKeys  |
| ListAccountAliases  | ListAssessmentRuns  | ListAttachedUserPolicies  | ListBuckets  |
| ListCertificates  | ListDistributions  | ListFindings  | ListFunctions20150331  |
| ListGroups  | ListInstanceProfiles  | ListSSHPublicKeys  | ListServiceSpecificCredentials  |
| ListTagsForResource  | ListUsers  | PutBucketAcl  | PutEvaluations  |
| PutMetricAlarm  | PutScalingPolicy  | RegisterTargets  | RevokeSecurityGroupIngress  |
| RunInstances  | StartAssessmentRun  | TerminateInstances  | UpdateAccessKey  |
| UpdateSecurityGroupRuleDescriptionsIngress  | -  | -  | -  |


The next step for me was to find out what exact data is stored in CludTrial:
```
index=botsv3 sourcetype=aws:cloudtrail | fieldsummary
```

Found "userIdentity.userName" which is the most aligned to what I was looking for to answer the question.
Finally enumerated the available user names:
```
index=botsv3 sourcetype=aws:cloudtrail | stats count by userIdentity.userName
```
🟢 **Answer**: bstoll,btun,splunk_access,web_admin

## ❓TASK❓ What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)  

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
🟢 **Answer**: userIdentity.sessionContext.mfaAuthenticated

## ❓TASK❓ What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)

Again had to check if there's any sourcetype that points to hardware-related logs
```
index=botsv3 | stats count by sourcetype
```
I found the sourcetype: "hardware" and its results all bring the same processor info
```
index=botsv3 sourcetype=hardware
```
🟢 **Answer**: E5-2676

## ❓TASK❓ Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.

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
One of these events is granting WRITE and READ permissions to "global/All users"
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

🟢 **Answer**: ab45689d-69cd-41e7-8705-5350402cf7ac

## ❓TASK❓ What is the name of the S3 bucket that was made publicly accessible?

Using the last query
```
index=botsv3 sourcetype=aws:cloudtrail bstoll eventName=PutBucketAcl
```
We need to expand the 'requestParameters' object to see this:
```
 requestParameters: { [-]
     AccessControlPolicy: { [+]
     }
     acl: [ [+]
     ]
     bucketName: frothlywebcode
   }
```
There we can identify the bucket name.

🟢 **Answer**: frothlywebcode

## ❓TASK❓ What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Provide just the file name and extension, not the full path. (Example: filename.docx instead of /mylogs/web/filename.docx)  

I can't see an event in CloudTrial that could be related to file uploads and listing by the events in the frothlywebcode bucket also does not gives any clues
```
index=botsv3 sourcetype=aws:cloudtrail  requestParameters.bucketName=frothlywebcode 
| stats count by eventName
```
I found (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#logging-data-events) that potentially data uploads to the bucket could be logged by 'AWS::S3' as per the service description:
> Amazon S3 object-level API activity (for example, GetObject, DeleteObject, and PutObject API operations) on buckets and objects in buckets.

Seems that the sourcetype could potentially be
```
aws:s3:accesslogs
```
Build a query to find all TXT-related events on the 'aws:s3:accesslogs' sourcetype:
```
index=botsv3 sourcetype=aws:s3:accesslogs "*.txt"
```
Found 3 logs. Now I need to crosscheck the time when the bucket was publicly accessible (8/20/18 1:01:46.000 PM) to one of the listed events.

The 3 listed events match the time before the ACL was changed to remove public access.
```
8/20/18
1:03:46.000 PM	
4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d frothlywebcode [20/Aug/2018:13:03:46 +0000] 35.182.246.222 - 6CF2A6F4DE3DC1E8 REST.GET.OBJECT OPEN_BUCKET_PLEASE_FIX.txt "GET /OPEN_BUCKET_PLEASE_FIX.txt HTTP/1.1" 200 - 377 377 14 13 "-" "aws-cli/1.14.8 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 botocore/1.8.12" -

    host = splunk.froth.ly
    source = s3://frothlyweblogs/s32018-07-26-01-25-30-F2258C3FF62970B6
    sourcetype = aws:s3:accesslogs

8/20/18
1:02:45.000 PM	
4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d frothlywebcode [20/Aug/2018:13:02:45 +0000] 52.66.146.128 - A01BFC3123EC114C REST.GET.BUCKET - "GET /?prefix=OPEN_BUCKET_PLEASE_FIX.txt&encoding-type=url HTTP/1.1" 200 - 575 - 11 10 "-" "Boto3/1.7.62 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 Botocore/1.8.12" -

    host = splunk.froth.ly
    source = s3://frothlyweblogs/s32018-07-26-01-20-56-19D73C05AA29AED8
    sourcetype = aws:s3:accesslogs

8/20/18
1:02:44.000 PM	
4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d frothlywebcode [20/Aug/2018:13:02:44 +0000] 52.66.146.128 - DF1BA98D9E2369B4 REST.PUT.OBJECT OPEN_BUCKET_PLEASE_FIX.txt "PUT /OPEN_BUCKET_PLEASE_FIX.txt HTTP/1.1" 200 - - 377 268 9 "-" "Boto3/1.7.62 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 Botocore/1.8.12" -

    host = splunk.froth.ly
    source = s3://frothlyweblogs/s32018-07-26-01-20-56-19D73C05AA29AED8
    sourcetype = aws:s3:accesslogs
```
The 3 events reference the same TXT file and the SR bucket (frothlywebcode).

Probably I could have refined the search by using the bucket name as filter:
```
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode "*.txt"
```

🟢 **Answer**: OPEN_BUCKET_PLEASE_FIX.txt

## ❓TASK❓ What is the size (in megabytes) of the .tar.gz file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Round to two decimal places without the unit of measure. Use 1024 for the byte conversion. Use a period (not a comma) as the radix character. 

In a similar way as the previous task, we could identify the .tar.gz file using:
```
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode "*.tar.gz"
```
I got multiple logs for multiple type of calls:
- REST.GET.OBJECT
- REST.HEAD.OBJECT
- REST.PUT.OBJECT
- REST.GET.BUCKETVERSIONS
- REST.GET.ACL
- REST.GET.BUCKET
  
I filtered then using just the REST.PUT.OBJECT call
```
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode REST.PUT.OBJECT "*.tar.gz"
```
This time I got only 3 logs but I can't specifically identify the file size. Used AI to help me analyze the log
```
help me analyze this log:
4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d frothlywebcode [20/Aug/2018:13:04:17 +0000] 35.182.246.222 - 372244DB57196FB9 REST.PUT.OBJECT frothly_html_memcached.tar.gz "PUT /frothly_html_memcached.tar.gz HTTP/1.1" 200 - - 3076532 981 49 "-" "Boto3/1.7.61 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 Botocore/1.8.12" -
```
AI response:
```
This log appears to be from AWS (Amazon Web Services), specifically from the S3 service, which is used for object storage. Here's the breakdown:

- `4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d` - This is possibly a SHA-256 hash, which could be used to uniquely identify the log entry.
- `frothlywebcode` - This could be the bucket name on S3.
- `[20/Aug/2018:13:04:17 +0000]` - The timestamp of when the action occurred.
- `35.182.246.222` - The IP address of the client that made the request. 
- `372244DB57196FB9` - This could be the request ID, which is unique for every request.
- `REST.PUT.OBJECT` - The operation that was performed. In this case, a `PUT` request was made, indicating that a file was uploaded.
- `frothly_html_memcached.tar.gz` - The object that was put onto the S3 bucket. It's a .tar.gz file, which is a Gzip compressed tar Archive file.
- `"PUT /frothly_html_memcached.tar.gz HTTP/1.1" 200` - This further confirms the `PUT` operation, the file involved, and the HTTP version used. The `200` is the HTTP status code for 'OK', indicating that the operation was successful.
- `3076532` - This is likely the size of the object in bytes.
- `981` - This could be the time taken to serve the request, in milliseconds.
- `49` - This could be the time taken to establish a connection, in milliseconds.
- `"Boto3/1.7.61 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 Botocore/1.8.12"` - This is the user agent string, which tells us that the client used the Boto3 library (version 1.7.61), Python version 2.7.14, and a Linux OS to make the request. Botocore is a low-level, core functionality library for AWS services and Boto3 depends on it.
```
So if the potential object size in bytes could be: 3076532 then:
```
3076532 bytes / 1024 = 3002.77 kilobytes
3002.77 kilobytes / 1024 = 2.93 megabytes
```
🟢 **Answer**: 2.93

## ❓TASK❓ A Frothly endpoint exhibits signs of coin mining activity. What is the name of the first process to reach 100 percent CPU processor utilization time from this activity on this endpoint? Answer guidance: Include any special characters/punctuation.

Seems that the "cpu" sourcetype could help here
```
index=botsv3 earliest=0 frothlywebcode sourceType=cpu
```
0 results xD

According to https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/US_SingleMetricPerInstance.html, the "CloudWatch" sourcetype could help us, the info that we're looking for could be in the "CPUUtilization" field
```
index=botsv3 sourcetype=aws:cloudwatch CPUUtilization
| table time, Maximum, metric_dimensions
```
I can't find any log with 100% CPU utilization, maybe I'm looking at the incorrect sourcetype?

Trying now with "ps"
```
index=botsv3 sourcetype=ps 
| table time, host, pctCPU, pctMEM, pid, process_name
```
This looks more promising but I still can't find a process with 100% CPU utilization the maximum is splunkd with 61%

This page https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo references to "perfmon" and "perfmonmk", we have "PerfmonMk:Process" to use in this splunk index.
```
index=botsv3 sourcetype=PerfmonMk:Process
| table host, instance, process_cpu_used_percent, process_id, process_name, source
```
I found the process!
| host | process_cpu_used_percent | process_id | process_name |
| --- | --- | --- | --- |
| BSTOLL-L | 100 | 8000| chrome#5 |

🟢 **Answer**: chrome#5

## ❓TASK❓ When a Frothly web server EC2 instance is launched via auto scaling, it performs automated configuration tasks after the instance starts. How many packages and dependent packages are installed by the cloud initialization script? Answer guidance: Provide the number of installed packages then number of dependent packages, comma separated without spaces.

I found some related sourcetypes that could be related: "cloud-init" or ”cloud-init-output” or "package"
This thread (https://serverfault.com/questions/228481/where-is-log-output-from-cloud-init-stored) points to "cloud-init"
```
index=botsv3 sourcetype=cloud-init
```
1,344 events but don't seem to provide details on installed packages
```
index=botsv3 sourcetype=cloud-init-output
```
23 events and each logs has a bunch more details
```
index=botsv3 sourcetype=package
```
8,720 events and don't seem to be related to EC2 initialization so I'll stick back with "cloud-init-output"
```
index=botsv3 sourcetype=cloud-init-output
```
"index=botsv3 sourcetype=cloud-init-output autoscale" and "index=botsv3 sourcetype=cloud-init-output autoscaling" proved to not be helpful at all

I see from here https://docs.aws.amazon.com/linux/al2023/ug/managing-repos-os-updates.html and here https://aws.amazon.com/blogs/mt/software-deployment-to-amazon-workspaces-using-aws-systems-manager/ that the output will show a "Transaction summary" with the packages installed after it runs, so:
```
index=botsv3 sourcetype=cloud-init-output "Transaction summary"
```
This brings 6 events and in 2 of them I found:
```
8/20/18
2:25:21.000 PM	
Cloud-init v. 0.7.6 running 'modules:final' at Thu, 26 Jul 2018 01:37:21 +0000. Up 11.07 seconds.
... 132 lines omitted ...
 php-xml            x86_64 5.3.29-1.8.amzn1           amzn-main           234 k
Transaction Summary
================================================================================
Install  7 Packages (+13 Dependent packages)
```
🟢 **Answer**: 7,13
