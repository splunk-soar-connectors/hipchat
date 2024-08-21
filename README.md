[comment]: # "Auto-generated SOAR connector documentation"
# HipChat

Publisher: Phantom  
Connector Version: 1.0.7  
Product Vendor: Atlassian  
Product Name: HipChat  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 4.0.1068  

This app integrates with HipChat to support different generic and investigative actions

[comment]: # "File: README.md"
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
**server_url** |  required  | string | Server URL (e.g. https://10.10.10.10)
**verify_server_cert** |  optional  | boolean | Verify Server Certificate
**api_token** |  required  | password | API token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list rooms](#action-list-rooms) - List non-archived rooms  
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
List non-archived rooms

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.id | numeric |  `hipchat room id`  |   1 
action_result.data.\*.is_archived | boolean |  |   True  False 
action_result.data.\*.links.members | string |  `url`  |   https://hipchat.cds.com/v2/room/1/member 
action_result.data.\*.links.participants | string |  `url`  |   https://hipchat.cds.com/v2/room/1/participant 
action_result.data.\*.links.self | string |  `url`  |   https://hipchat.cds.com/v2/room/1 
action_result.data.\*.links.webhooks | string |  `url`  |   https://hipchat.cds.com/v2/room/1/webhook 
action_result.data.\*.name | string |  `hipchat room name`  |   Default 
action_result.data.\*.privacy | string |  |   public 
action_result.data.\*.version | string |  |   C1MNIO9A 
action_result.summary.total_rooms | numeric |  |   104 
action_result.message | string |  |   Total rooms: 104 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list users'
List all active users

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.id | numeric |  `hipchat user id`  |   1 
action_result.data.\*.links.self | string |  `url`  |   https://hipchat.cds.com/v2/user/1 
action_result.data.\*.mention_name | string |  `user name`  |   Testuser 
action_result.data.\*.name | string |  |   Test user 
action_result.data.\*.version | string |  |   A18E977A 
action_result.summary.total_users | numeric |  |   6 
action_result.message | string |  |   Total users: 6 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'upload file'
Upload file to HipChat

Type: **generic**  
Read only: **True**

If parameter <b>destination_type</b> is User, parameter <b>destination</b> can be ID/mention name/email of a user. <br>If parameter <b>destination_type</b> is Room, parameter <b>destination</b> can be ID/name of a room.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**destination_type** |  required  | Type of destination | string | 
**destination** |  required  | Room or User to upload to | string |  `email`  `user name`  `hipchat user id`  `hipchat room name`  `hipchat room id` 
**vault_id** |  required  | Vault ID of file to send | string |  `vault id`  `sha1` 
**message** |  optional  | Message to send with file | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.destination | string |  `email`  `user name`  `hipchat room id`  `hipchat room name`  `hipchat user id`  |   test_email@abc.com 
action_result.parameter.destination_type | string |  |   User  Room 
action_result.parameter.message | string |  |   test message 
action_result.parameter.vault_id | string |  `sha1`  `vault id`  |   343c4d96e55471f29a5f5717ad2157513d45bbf4 
action_result.message | string |  |   File uploaded successfully 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'send message'
Send message to HipChat user

Type: **generic**  
Read only: **True**

If parameter <b>destination_type</b> is User, parameter <b>destination</b> can be ID/mention name/email of a user. <br>If parameter <b>destination_type</b> is Room, parameter <b>destination</b> can be ID/name of a room.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**destination_type** |  required  | Type of destination | string | 
**destination** |  required  | Room or User to send message to | string |  `email`  `user name`  `hipchat room id`  `hipchat user id`  `hipchat room name` 
**message** |  required  | Message to send | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.destination | string |  `email`  `user name`  `hipchat user id`  `hipchat room name`  `hipchat room id`  |   test user 
action_result.parameter.destination_type | string |  |   User  Room 
action_result.parameter.message | string |  |   Test message 
action_result.data.\*.id | string |  |   479c49b6-210c-47ad-b3be-e679c546409d 
action_result.data.\*.timestamp | string |  |   2017-12-27T05:31:59Z 887972 
action_result.message | string |  |   Message sent 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 