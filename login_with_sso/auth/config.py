"""
 Copyright 2022 SeaTalk Open Platform

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
SESSION_EXPIRE_TIME = 48 * 3600

HTTP_TIMEOUT = 5
API_HOST = 'https://openapi.seatalk.io'
APP_ID = ''
APP_SECRET = ''
PATH_APP_ACCESS_TOKEN = "/auth/app_access_token"
PATH_SSO_VERIFY = "/sso/v2/verify"
PATH_GET_EMPLOYEE = "/contacts/v2/profile"

REDIS_URL = "redis://127.0.0.1:6379/0"
REDIS_MAX_CONNECTIONS = 10
REDIS_HEALTH_CHECK_INTERVAL = 30

# for test
TEST_FLAG = "test_sso_token"
TEST_EMPLOYEE_CODE = ""

# app return code
APP_SUCCESS = 0
APP_PARAM_INVALID = 1
APP_SESS_ID_INVALID = 2
APP_GET_ACCESS_TOKEN_HTTP_CODE_EXCEPTION = 10001
APP_GET_ACCESS_TOKEN_SOP_CODE_EXCEPTION = 10002
APP_GET_ACCESS_TOKEN_RESPONSE_EXCEPTION = 10003
APP_POST_VERIFY_HTTP_CODE_EXCEPTION = 10011
APP_POST_VERIFY_SOP_CODE_EXCEPTION = 10012
APP_POST_VERIFY_RESPONSE_EXCEPTION = 10013
APP_GET_EMPLOYEE_PROFILE_HTTP_CODE_EXCEPTION = 10021
APP_GET_EMPLOYEE_PROFILE_SOP_CODE_EXCEPTION = 10022
APP_GET_EMPLOYEE_PROFILE_RESPONSE_EXCEPTION = 10023
APP_REDIS_GET_FAILED = 20001
APP_REDIS_SET_FAILED = 20002

APP_ERR_MSG_DICT = {
    APP_SUCCESS: "success",
    APP_PARAM_INVALID: "not exists",
    APP_SESS_ID_INVALID: "session id is invalid",
    APP_GET_ACCESS_TOKEN_HTTP_CODE_EXCEPTION: "get app access token http code exception",
    APP_GET_ACCESS_TOKEN_SOP_CODE_EXCEPTION: "get app access token failed, sop code exception",
    APP_GET_ACCESS_TOKEN_RESPONSE_EXCEPTION: "get app access token resp exception",
    APP_POST_VERIFY_HTTP_CODE_EXCEPTION: "post sso v2 verify http code exception",
    APP_POST_VERIFY_SOP_CODE_EXCEPTION: "post sso v2 verify failed, sop code exception",
    APP_POST_VERIFY_RESPONSE_EXCEPTION: "post sso v2 verify resp exception",
    APP_GET_EMPLOYEE_PROFILE_HTTP_CODE_EXCEPTION: "get employee profile http code exception",
    APP_GET_EMPLOYEE_PROFILE_SOP_CODE_EXCEPTION: "get employee profile, sop code exception",
    APP_REDIS_SET_FAILED: "redis set failed",
}
