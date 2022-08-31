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
import time
from http import HTTPStatus
import flask
from flask import request, jsonify
from flask_cors import CORS
from redis.client import Redis
from redis.connection import ConnectionPool

from login_with_sso.auth import config
from login_with_sso.auth.seatalk import SeaTalkClient
from login_with_sso.auth.session import SessionClient

app = flask.Flask(__name__)
logger = logging.getLogger(__name__)
CORS(app, supports_credentials=True)
redis_client = Redis(
    connection_pool=ConnectionPool.from_url(config.REDIS_URL, max_connections=config.REDIS_MAX_CONNECTIONS,
                                            health_check_interval=config.REDIS_HEALTH_CHECK_INTERVAL))
sop_client = SeaTalkClient(config.APP_ID, config.APP_SECRET, config.API_HOST)
session_client = SessionClient(redis_client)


@app.route('/platform/echo', methods=['POST'])
def Echo():
    req = request.get_json(force=True)
    res = {'pong': req.get('ping', '')}
    return auth_response(res, config.APP_SUCCESS)


@app.route('/platform/user/seatalk_login', methods=['POST'])
def SeaTalk_login():
    # 1.Parse parameters
    req = request.get_json(force=True)
    sso_token = req.get('sso_token')
    logger.info("access log, sso_token: %s" % sso_token)
    if not sso_token:
        logger.error("seaTalk auth failed, sso_token is empty! sso_token: %s" % sso_token)
        return auth_response({}, config.APP_PARAM_INVALID)

    # 2.Get app_access_token
    app_code, access_token = get_app_access_token_with_cache()
    if app_code != config.APP_SUCCESS:
        return app_code, None

    # 3.Verify sso_token, get employee_code
    if sso_token == config.TEST_FLAG:
        employee_code = config.TEST_EMPLOYEE_CODE
    else:
        app_code, employee_code = sop_client.http_post_sso_verify(sso_token, access_token)
        if app_code != config.APP_SUCCESS:
            return app_code, None

    # 4.Get employee info
    app_code, employee = sop_client.http_get_employee(employee_code, access_token)
    if app_code != config.APP_SUCCESS:
        return app_code, None

    # 5.Generate APP session
    app_code, session_id = session_client.gen_session(employee)
    if app_code != config.APP_SUCCESS:
        return app_code, {}

    # 6.Return
    res = {
        'employee': sop_employee_to_app_employee(employee),
        'session_id': session_id,
        'expire_time': int(time.time()) + config.SESSION_EXPIRE_TIME
    }
    resp = auth_response(res, app_code)
    resp.set_cookie("session_id", res['session_id'], max_age=config.SESSION_EXPIRE_TIME)
    return resp


def get_app_access_token_with_cache():
    # 1.Get app_access_token form redis, weak dependence
    try:
        token_info = redis_client.get(sop_client.get_app_access_token_key())
        if token_info is not None:
            return config.APP_SUCCESS, json.loads(token_info)['app_access_token']
    except Exception as e:
        logger.error("getAppAccessTokenWithCache get from redis failed, err: %s" % str(e))

    # 2.Http request app_access_token
    app_code, token_info = sop_client.http_post_app_access_token()
    if app_code != config.APP_SUCCESS:
        return app_code, None

    # 3.Set app_access_token to redis
    cache_interval = token_info['expire'] - int(time.time()) - 60
    try:
        val = json.dumps(token_info, ensure_ascii=False)
        redis_client.setex(sop_client.get_app_access_token_key(), cache_interval, val)
    except Exception as e:
        logger.exception("getAppAccessTokenWithCache set redis failed, err: %s" % str(e))
        return config.APP_REDIS_SET_FAILED, None


def sop_employee_to_app_employee(employee):
    return {"employee_code": employee['employee_code'], "name": employee['name'],
            "email": employee['email'], "avatar": employee['avatar']}


def auth_response(res, app_code):
    logtail = "res: %s app_code: %s" % (str(res), app_code)

    res['code'] = app_code
    res['msg'] = config.APP_ERR_MSG_DICT.get(app_code)

    try:
        resp = jsonify(res)
        resp.status_code = HTTPStatus.OK
        logging.getLogger(__name__).info("return log, %s" % logtail)
        return resp
    except Exception as e:
        logging.getLogger(__name__).error("make AuthResponse failed, err:%s" % e)


if __name__ == '__main__':
    app.run()
