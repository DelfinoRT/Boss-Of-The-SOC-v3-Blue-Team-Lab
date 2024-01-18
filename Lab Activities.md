🟢 **List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)**  

First I did a quick search and found out that the only index available was "botsv3"
```
index=* | stats count by index
```
Then I went to investigate where AWS stores logs for user access and got to: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-logging-and-monitoring.html, AWS CloudTrail made the most sense.
```
index=botsv3 | stats count by sourcetype
```
Sourcetype "aws:cloudtrail" identified

The next step for me was to find out what exact data is stored in CludTrial:
```
index=botsv3 sourcetype=aws:cloudtrail | fieldsummary
```
Found "userIdentity.userName" which is the most aligned to what I was looking for to answer the question.
Finally enumerated the available user names:
```
index=botsv3 sourcetype=aws:cloudtrail | stats count by userIdentity.userName
```
**Answer**: bstoll,btun,splunk_access,web_admin

🟢 **What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)**  

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
I found the field I was looking for!
**Answer**: userIdentity.sessionContext.mfaAuthenticated
