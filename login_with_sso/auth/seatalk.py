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
import json
import logging
import requests
from login_with_sso.auth import config
from http import HTTPStatus

SOP_SUCCESS = 0


class SeaTalkClient(object):
    def __init__(self, app_id, app_secret, api_host):
        super().__init__()
        self.__logger = logging.getLogger(__name__)
        self.__app_id = app_id
        self.__app_secret = app_secret
        self.__api_host = api_host
        self.session = requests.session()
        self.timeout = config.HTTP_TIMEOUT

    def get_url(self, path):
        return "%s%s" % (self.__api_host, path)

    def get_app_access_token_data(self):
        return {"app_id": self.__app_id, "app_secret": self.__app_secret}

    def get_app_access_token_key(self):
        return "sop_access_token_%s" % self.__app_id

    def http_post_app_access_token(self):
        forms = json.dumps(self.get_app_access_token_data(), ensure_ascii=False).encode('utf8')
        r = self.session.post(self.get_url(config.PATH_APP_ACCESS_TOKEN), data=forms, timeout=self.timeout,
                              verify=False)
        resp = json.loads(r.text)

        if r.status_code != HTTPStatus.OK:
            self.__logger.error(
                "HttpPostAppAccessToken http code error, http_code:%d resp:%s " % (r.status_code, str(resp)))
            return config.APP_GET_ACCESS_TOKEN_HTTP_CODE_EXCEPTION, ""

        if resp['code'] != SOP_SUCCESS:
            self.__logger.error(
                "HttpPostAppAccessToken sop code error, http_code:%d resp:%s " % (r.status_code, str(resp)))
            return config.APP_GET_ACCESS_TOKEN_SOP_CODE_EXCEPTION, ""

        if 'app_access_token' not in resp or 'expire' not in resp:
            self.__logger.error("HttpPostAppAccessToken resp error, http_code:%d resp:%s " % (r.status_code, str(resp)))
            return config.APP_GET_ACCESS_TOKEN_RESPONSE_EXCEPTION, ""

        return config.APP_SUCCESS, resp

    def http_post_sso_verify(self, sso_token, app_access_token):
        logtail = "sso_token: %s app_access_token: %s" % (sso_token, app_access_token)
        forms = json.dumps(get_app_sso_verify_data(sso_token), ensure_ascii=False).encode('utf8')
        self.session.headers.update(get_header("json", app_access_token))
        r = self.session.post(self.get_url(config.PATH_SSO_VERIFY), data=forms, timeout=self.timeout, verify=False)
        resp = json.loads(r.text)
        if r.status_code != HTTPStatus.OK:
            self.__logger.error(
                "HttpPostSSOVerify http code error, http_code:%d verify_resp:%s %s" % (
                    r.status_code, str(resp), logtail))
            return config.APP_POST_VERIFY_HTTP_CODE_EXCEPTION, None

        if resp['code'] != SOP_SUCCESS:
            self.__logger.error(
                "HttpPostSSOVerify sop code error, http_code:%d verify_resp:%s app_access_token:%s %s" % (
                    r.status_code, str(resp), app_access_token, logtail))
            return config.APP_POST_VERIFY_SOP_CODE_EXCEPTION, None

        if 'profile' not in resp or resp['profile'] is None or resp['profile']['employee_code'] is None:
            self.__logger.error("HttpPostSSOVerify resp error, http_code:%d verify_resp:%s app_access_token:%s %s" % (
                r.status_code, str(resp), app_access_token, logtail))
            return config.APP_POST_VERIFY_RESPONSE_EXCEPTION, None

        return config.APP_SUCCESS, resp['profile']['employee_code']

    def http_get_employee(self, employee_code, access_token):
        logtail = "employee_code: %s access_token: %s" % (employee_code, access_token)

        path = config.PATH_GET_EMPLOYEE + "?employee_code=%s" % employee_code
        self.session.headers.update(get_header("form", access_token))
        r = self.session.get(self.get_url(path), timeout=self.timeout, verify=False)
        resp = json.loads(r.text)

        if r.status_code != HTTPStatus.OK:
            self.__logger.error(
                "HttpGetEmployee http code error, http_code: %d app_id: %s %s" % (
                    r.status_code, self.__app_id, logtail))
            return config.APP_GET_EMPLOYEE_PROFILE_HTTP_CODE_EXCEPTION, None

        if resp['code'] != SOP_SUCCESS:
            self.__logger.error("HttpGetEmployee sop code error, resp: <%s> %s" % (str(resp), logtail))
            return config.APP_GET_EMPLOYEE_PROFILE_SOP_CODE_EXCEPTION, None

        if 'employees' not in resp or not resp['employees']:
            self.__logger.error("HttpGetEmployee resp error, resp: <%s> %s" % (str(resp), logtail))
            return config.APP_GET_EMPLOYEE_PROFILE_RESPONSE_EXCEPTION, None

        return config.APP_SUCCESS, resp['employees'][0]


def get_header(content_type, access_token):
    if content_type == "form":
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain'}
    else:
        headers = {'Content-type': 'application/json; charset=utf-8', 'Accept': 'text/plain'}
    if access_token is not None:
        headers['Authorization'] = "Bearer %s" % access_token
    return headers


def get_app_sso_verify_data(sso_token):
    return {"token": sso_token}
