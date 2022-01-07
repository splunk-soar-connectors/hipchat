[comment]: # "Auto-generated SOAR connector documentation"
# HipChat

Publisher: Phantom  
Connector Version: 1\.0\.5  
Product Vendor: Atlassian  
Product Name: HipChat  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.0\.1068  

This app integrates with HipChat to support different generic and investigative actions

[comment]: # "File: readme.md"
[comment]: # "Copyright (c) 2018-2019 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
You need to generate the API token from your HipChat account with scopes Send Message and View
Group.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a HipChat asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL \(e\.g\. https\://10\.10\.10\.10\)
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate
**api\_token** |  required  | password | API token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list rooms](#action-list-rooms) - List non\-archived rooms  
[list users](#action-list-users) - List all active users  
[upload file](#action-upload-file) - Upload file to HipChat  
[send message](#action-send-message) - Send message to HipChat user  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list rooms'
List non\-archived rooms

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.id | numeric |  `hipchat room id` 
action\_result\.data\.\*\.is\_archived | boolean | 
action\_result\.data\.\*\.links\.members | string |  `url` 
action\_result\.data\.\*\.links\.participants | string |  `url` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.links\.webhooks | string |  `url` 
action\_result\.data\.\*\.name | string |  `hipchat room name` 
action\_result\.data\.\*\.privacy | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_rooms | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
List all active users

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.id | numeric |  `hipchat user id` 
action\_result\.data\.\*\.links\.self | string |  `url` 
action\_result\.data\.\*\.mention\_name | string |  `user name` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload file'
Upload file to HipChat

Type: **generic**  
Read only: **True**

If parameter <b>destination\_type</b> is User, parameter <b>destination</b> can be ID/mention name/email of a user\. <br>If parameter <b>destination\_type</b> is Room, parameter <b>destination</b> can be ID/name of a room\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**destination\_type** |  required  | Type of destination | string | 
**destination** |  required  | Room or User to upload to | string |  `email`  `user name`  `hipchat user id`  `hipchat room name`  `hipchat room id` 
**vault\_id** |  required  | Vault ID of file to send | string |  `vault id`  `sha1` 
**message** |  optional  | Message to send with file | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination | string |  `email`  `user name`  `hipchat room id`  `hipchat room name`  `hipchat user id` 
action\_result\.parameter\.destination\_type | string | 
action\_result\.parameter\.message | string | 
action\_result\.parameter\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'send message'
Send message to HipChat user

Type: **generic**  
Read only: **True**

If parameter <b>destination\_type</b> is User, parameter <b>destination</b> can be ID/mention name/email of a user\. <br>If parameter <b>destination\_type</b> is Room, parameter <b>destination</b> can be ID/name of a room\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**destination\_type** |  required  | Type of destination | string | 
**destination** |  required  | Room or User to send message to | string |  `email`  `user name`  `hipchat room id`  `hipchat user id`  `hipchat room name` 
**message** |  required  | Message to send | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination | string |  `email`  `user name`  `hipchat user id`  `hipchat room name`  `hipchat room id` 
action\_result\.parameter\.destination\_type | string | 
action\_result\.parameter\.message | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 