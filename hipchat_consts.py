# File: hipchat_consts.py
#
# Copyright (c) 2018-2019 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
HIPCHAT_CONFIG_SERVER_URL = 'server_url'
HIPCHAT_CONFIG_API_TOKEN = 'api_token'
HIPCHAT_CONFIG_VERIFY_SSL = 'verify_server_cert'
HIPCHAT_CONNECTION_TEST_MSG = 'Querying endpoint to verify the credentials provided'
HIPCHAT_REST_TEST_CONNECTIVITY = '/v2/user'
HIPCHAT_REST_SEND_MESSAGE_ROOM = '/v2/room/{room}/message'
HIPCHAT_REST_SEND_MESSAGE = '/v2/user/{user}/message'
HIPCHAT_REST_UPLOAD_FILE = '/v2/user/{user}/share/file'
HIPCHAT_REST_UPLOAD_FILE_ROOM = '/v2/room/{room}/share/file'
HIPCHAT_REST_LIST_ROOMS = '/v2/room'
HIPCHAT_TEST_CONNECTIVITY_FAIL = 'Test Connectivity Failed'
HIPCHAT_TEST_CONNECTIVITY_PASS = 'Test Connectivity Passed'
HIPCHAT_PARAM_DESTINATION = 'destination'
HIPCHAT_PARAM_DESTINATION_TYPE = 'destination_type'
HIPCHAT_PARAM_MESSAGE = 'message'
HIPCHAT_USER_NOT_AVAILABLE = 'User not available'
HIPCHAT_START_INDEX = 'start-index'
HIPCHAT_PAYLOAD_BOUNDARY = 'phantom_boundary'
HIPCHAT_UPLOAD_FILE_PAYLOAD = """\
--{boundary}
Content-Type: application/json; charset=UTF-8
Content-Disposition: attachment; name="metadata"

{message}
--{boundary}
Content-Disposition: attachment; name="file"; filename="{file_name}"

{file_data}
--{boundary}--\
"""
