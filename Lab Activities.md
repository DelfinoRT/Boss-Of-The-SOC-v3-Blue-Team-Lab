🟢 **
List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)**  

Firs I did a quick search and found out that the only index available was "botsv3"
```
index=*|stats count by index|fields index
```
| eventcount summarize=false index=* index=_* | dedup index | fields index
I went to investigate where AWS stores logs for user access and got to: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-logging-and-monitoring.html
 eventID: 7e8df385-9e9c-4111-a774-47e01a228656 
