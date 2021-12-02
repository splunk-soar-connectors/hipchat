# File: hipchat_connector.py
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
import requests
import json
import urllib
from bs4 import BeautifulSoup

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

from hipchat_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class HipchatConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(HipchatConnector, self).__init__()

        self._state = None

        self._server_url = None
        self._api_token = None
        self._verify_server_cert = False

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._server_url = config[HIPCHAT_CONFIG_SERVER_URL].strip("/")
        self._verify_server_cert = config.get(HIPCHAT_CONFIG_VERIFY_SSL, False)
        self._api_token = config[HIPCHAT_CONFIG_API_TOKEN]

        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if 200 <= status_code < 399:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, message), None)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """ This function is used to process json response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        if resp_json['error']['message']:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(resp_json['error']['code'],
                                                                                         resp_json['error']['message'])

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """ This function is used to process html response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, timeout=None,
                        method="get"):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
            action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        if not headers:
            headers = dict()

        headers['Authorization'] = 'Bearer {token}'.format(token=self._api_token)

        headers['Content-Type'] = 'application/json'

        if self.get_action_identifier() == 'upload_file':
            headers['Content-Type'] = 'multipart/related; boundary={boundary}'.format(
                boundary=HIPCHAT_PAYLOAD_BOUNDARY)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._server_url + endpoint

        try:
            r = request_func(url, data=data, headers=headers, verify=self._verify_server_cert,
                             params=params, timeout=timeout)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(HIPCHAT_CONNECTION_TEST_MSG)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_TEST_CONNECTIVITY,
                                                 action_result=action_result, timeout=30)

        if phantom.is_fail(ret_val):
            self.save_progress(HIPCHAT_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.save_progress(HIPCHAT_TEST_CONNECTIVITY_PASS)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_upload_file(self, param):
        """ This function is used to share the file with HipChat user.

        :param param: Dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        destination_type = param[HIPCHAT_PARAM_DESTINATION_TYPE]
        destination = urllib.quote_plus(param[HIPCHAT_PARAM_DESTINATION])
        vault_id = param['vault_id']
        message = param.get(HIPCHAT_PARAM_MESSAGE, '')

        vault_file_info = Vault.get_file_info(vault_id=vault_id)

        if not vault_file_info:
            self.debug_print('Invalid parameter vault_id')
            action_result.set_status(phantom.APP_ERROR, 'Invalid parameter vault_id')
            return action_result.get_status()

        msg = json.dumps({HIPCHAT_PARAM_MESSAGE: message})

        with open(vault_file_info[0]['path'], 'rb') as vault_file:
            vault_file_data = vault_file.read()

        payload = HIPCHAT_UPLOAD_FILE_PAYLOAD.format(message=msg, boundary=HIPCHAT_PAYLOAD_BOUNDARY,
                                                     file_data=vault_file_data, file_name=vault_file_info[0]['name'])

        if destination_type == 'Room':
            # make rest call
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_UPLOAD_FILE_ROOM.format(room=destination),
                                                     action_result=action_result, data=payload, method='post')
        else:
            # make rest call
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_UPLOAD_FILE.format(user=destination),
                                                     action_result=action_result, data=payload, method='post')

            # If API call fails, it is possible that user has entered the username
            if phantom.is_fail(ret_val):
                # Add @ in encoded form at beginning
                destination = '%40{destination}'.format(destination=destination)

                ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_UPLOAD_FILE.format(user=destination),
                                                         action_result=action_result, method='post', data=payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, 'File uploaded successfully')

    def _handle_send_message(self, param):
        """ This function is used to send the message to specific user.

        :param param: Dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        destination_type = param[HIPCHAT_PARAM_DESTINATION_TYPE]
        destination = urllib.quote_plus(param[HIPCHAT_PARAM_DESTINATION])
        message = param[HIPCHAT_PARAM_MESSAGE]

        data = {HIPCHAT_PARAM_MESSAGE: message}

        if destination_type == 'Room':
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_SEND_MESSAGE_ROOM.format(room=destination),
                                                     action_result=action_result, method='post', data=json.dumps(data))
        else:
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_SEND_MESSAGE.format(user=destination),
                                                     action_result=action_result, method='post', data=json.dumps(data))

            # If it fails, it is possible that user has entered the username
            if phantom.is_fail(ret_val):

                # Add @ in encoded form at the beginning
                destination = '%40{destination}'.format(destination=destination)
                ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_SEND_MESSAGE.format(user=destination),
                                                         action_result=action_result, method='post',
                                                         data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, status_message='Message sent')

    def _handle_list_rooms(self, param):
        """ This function is used to list all non-archived rooms.

        :param param: Dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        start_index = 0

        while True:

            param = {HIPCHAT_START_INDEX: start_index}
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_LIST_ROOMS, action_result=action_result,
                                                     params=param)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # If room details are empty in response, no more rooms are available
            if not response['items']:
                break

            for room in response['items']:
                action_result.add_data(room)

            start_index += 100

        summary = action_result.update_summary({})
        summary['total_rooms'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):
        """ This function is used to list all users.

        :param param: Dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        start_index = 0

        while True:

            param = {HIPCHAT_START_INDEX: start_index}
            ret_val, response = self._make_rest_call(endpoint=HIPCHAT_REST_TEST_CONNECTIVITY, params=param,
                                                     action_result=action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # If user details are empty in response, no more users are available
            if not response['items']:
                break

            for user in response['items']:
                action_result.add_data(user)

            start_index += 100

        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'upload_file': self._handle_upload_file,
            'send_message': self._handle_send_message,
            'list_rooms': self._handle_list_rooms,
            'list_users': self._handle_list_users
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print ("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    if len(sys.argv) < 2:
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HipchatConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
