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
import logging
import json
import string
import random
from login_with_sso.auth import config


def get_session_redis_key(session_id):
    return "session_id_%s" % session_id


def gen_session_id():
    return "".join(random.choices(string.ascii_letters, k=32))


class SessionClient(object):
    def __init__(self, redis):
        super().__init__()
        self.__logger = logging.getLogger(__name__)
        self.__redis = redis

    def gen_session(self, session_value):
        try:
            session_id = gen_session_id()
            val = json.dumps(session_value, ensure_ascii=False)
            self.__redis.setex(get_session_redis_key(session_id), config.SESSION_EXPIRE_TIME, val)
            self.__logger.info("GenSession success, session_id: %s" % session_id)
            return config.APP_SUCCESS, session_id

        except BaseException as e:
            self.__logger.error("redis set or json dumps failed, err: %s" % str(e))
            return config.APP_REDIS_SET_FAILED, ""

    def get_session(self, session_id):
        try:
            val = self.__redis.get(get_session_redis_key(session_id))
            if val is None:
                self.__logger.warning("redis get sess_info not found, session_id: %s" % session_id)
                return config.APP_SESS_ID_INVALID, None
            return config.APP_SUCCESS, json.loads(val)

        except BaseException as e:
            self.__logger.error("redis get or json loads failed, err: %s" % str(e))
            return config.APP_REDIS_GET_FAILED, ""
