import io
import json
from copy import deepcopy
from datetime import timedelta
import traceback
from functools import wraps

import quart
from PIL import Image
from quart import request, Blueprint, send_file, send_from_directory
from quart_rate_limiter import RateLimiter, rate_limit, RateLimitExceeded
from quart_auth import AuthUser, QuartAuth, Unauthorized, current_user, login_required, login_user, logout_user
from quart_compress import Compress
import secrets
import os
from typing import Callable, Coroutine, Any
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

from ..module.accountmgr import Account, AccountManager, UserException, instance as usermgr, AccountException
from ..constants import CACHE_DIR
from ..module.modulebase import eResultStatus, ModuleResult
from ..module.modulemgr import TaskResult

CACHE_HTTP_DIR = os.path.join(CACHE_DIR, 'http_server')

PATH = os.path.dirname(os.path.abspath(__file__))
static_path = os.path.join(PATH, 'ClientApp')
static_path_new = os.path.join(PATH, 'ClientAppVue')

class HttpServer:

    def __init__(self, host = '0.0.0.0', port = 2, qq_only = False):

        self.web = Blueprint('web', __name__, static_folder=static_path_new)

        self.api = Blueprint('api', __name__, url_prefix = "/api")

        self.app = Blueprint('app', __name__, url_prefix = "/daily")

        self.quart = quart.Quart(__name__)
        QuartAuth(self.quart, cookie_secure=False)
        RateLimiter(self.quart)
        Compress(self.quart)
        self.quart.secret_key = secrets.token_urlsafe(16)
        self.super_secret = self._init_secret()
        self.app.register_blueprint(self.web)
        self.app.register_blueprint(self.api)

        self.host = host
        self.port = port
        self.configure_routes()
        self.qq_only = qq_only

    def _init_secret(self):
        path = os.path.join(CACHE_HTTP_DIR, 'server_secret')
        if not os.path.exists(path):
            with open(path, 'w') as f:
                f.write(secrets.token_urlsafe(256))
        with open(path, 'r') as f:
            secret = f.read()
        return secret

    @staticmethod
    def wrapaccount(readonly = False):
        def wrapper(func: Callable[..., Coroutine[Any, Any, Any]]):
            async def inner(accountmgr: AccountManager, acc: str, *args, **kwargs):
                if acc:
                    try:
                        async with accountmgr.load(acc, readonly) as mgr:
                            return await func(mgr, *args, **kwargs)
                    except AccountException as e:
                        return str(e), 400
                    except Exception as e:
                        traceback.print_exc()
                        return "服务器发生错误", 500
                else:
                    return "Please specify an account", 400
            inner.__name__ = func.__name__
            return inner
        return wrapper

    @staticmethod
    def wrapaccountmgr(readonly = False):
        def wrapper(func: Callable[..., Coroutine[Any, Any, Any]]):
            async def inner(*args, **kwargs):
                qid: str = current_user.auth_id
                async with usermgr.load(qid, readonly) as mgr:
                    return await func(accountmgr = mgr, *args, **kwargs)
            inner.__name__ = func.__name__
            return inner
        return wrapper

    @staticmethod
    def check_secret(secret):
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                data = await request.get_json()
                if 'secret' in data and data['secret'] == secret:
                    return await func(*args, **kwargs)
                else:
                    return "incorrect", 403
            return wrapper
        return decorator

    def configure_routes(self):

        @self.api.errorhandler(RateLimitExceeded)
        async def handle_rate_limit_exceeded_error(error):
            return "您冲得太快了，休息一下吧", 429

        @self.api.errorhandler(Unauthorized)
        async def redirect_to_login(*_: Exception):
            return "未登录，请登录", 401

        @self.api.route('/account', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        async def get_info(accountmgr: AccountManager):
            return await accountmgr.generate_info(), 200

        @self.api.route('/account', methods = ["PUT"])
        @login_required
        @HttpServer.wrapaccountmgr()
        async def put_info(accountmgr: AccountManager):
            data = await request.get_json()
            default_accont = data.get('default_account', '')
            if default_accont:
                accountmgr.set_default_account(default_accont)
            return "保存成功", 200

        @self.api.route('/account', methods = ["POST"])
        @login_required
        @HttpServer.wrapaccountmgr()
        async def create_account(accountmgr: AccountManager):
            try:
                data = await request.get_json()
                acc = data.get("alias", "")
                accountmgr.create_account(acc.strip())
                return "创建账号成功", 200
            except AccountException as e:
                traceback.print_exc()
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/sync', methods = ["POST"])
        @login_required
        @HttpServer.wrapaccountmgr()
        async def sync_account_config(accountmgr: AccountManager):
            try:
                data = await request.get_json()
                acc = data.get("alias", "")
                target_acc = data.get("target", [])  # target_acc 可空，为空则同步所有账号
                if acc not in accountmgr.accounts_map():
                    return "账号不存在", 400
                async with accountmgr.load(acc) as mgr:
                    for ano in accountmgr.accounts_map():
                        if ano != acc and (not target_acc or ano in target_acc):
                            async with accountmgr.load(ano) as other:
                                other.data_new.account_config = mgr.data_new.account_config
                return "配置同步成功", 200
            except AccountException as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly=True)
        async def get_account(account: Account):
            return account.generate_info(), 200

        @self.api.route('/account/<string:acc>', methods = ["PUT", "DELETE"])
        @login_required
        @HttpServer.wrapaccountmgr()
        @HttpServer.wrapaccount()
        async def update_account(account: Account):
            if request.method == "PUT":
                data = await request.get_json()
                if 'username' in data:
                    # account.data.username = data['username']  # 已更改
                    account.data_new.account_username = data['username']
                    account.data_new.game_data = {}
                if 'password' in data:
                    # account.data.password = data['password']  # 已更改
                    account.data_new.account_password = data['password']
                return "保存账户信息成功", 200
            elif request.method == "DELETE":
                account.delete()
                return "删除账户信息成功", 200
            else:
                return "", 404

        @self.api.route('/account/<string:acc>/daily', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly= True)
        async def get_daily_config(mgr: Account):
            if request.method == 'GET':
                return mgr.generate_daily_info()
            else:
                return "", 404

        @self.api.route('/account/<string:acc>/tools', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly= True)
        async def get_tools_config(mgr: Account):
            if request.method == 'GET':
                return mgr.generate_tools_info()
            else:
                return "", 404

        @self.api.route('/account/<string:acc>/config', methods = ['PUT'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount()
        async def put_config(mgr: Account):
            data = await request.get_json()
            # mgr.data.config.update(data)  # 已更改
            mgr.update_config(data)
            return "配置保存成功", 200

        @self.api.route('/account/<string:acc>/do_daily', methods = ['POST'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly=True)
        @HttpServer.wrapaccount()
        async def do_daily(mgr: Account):
            data = await request.get_json()
            is_text = data.get("text_result", False)
            # data = await request.get_json()
            try:
                result_item = await mgr.do_daily()
                # result = json.loads(result_item.result_json)
                resp = mgr.generate_result_info(result_item)
                if not is_text:
                    resp['image'] = mgr.generate_img_base64(Image.open(await mgr.load_daily_image(result_item)))
                return resp, 200
            except ValueError as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>/do_single', methods = ['POST'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly=True)
        @HttpServer.wrapaccount()
        async def do_single(mgr: Account):
            data = await request.get_json()
            is_text = data.get("text_result", False)
            order = data.get("order", [])
            resp = {
                "order": order,
                "status": '',
                "time": '',
                "result": {}
            }
            try:
                if len(order) == 0:
                    raise ValueError("请指定要执行的功能")
                if len(order) == 1:
                    result = await mgr.do_from_key(deepcopy(mgr.client.keys), order[0])
                    status = result.result_status
                else:
                    result, status = await mgr.do_from_multi_key(deepcopy(mgr.client.keys), order)

                if not is_text:
                    mime = 'image/jpeg'
                    if len(order) == 1:
                        resp['result']['status'] = result.result_status.value
                        res_img = Image.open(await mgr.load_single_image(result))
                    else:
                        resp['result']['status'] = status.value
                        res_img = await mgr.generate_image(result, status)
                    byte_arr = io.BytesIO()
                    res_img.save(byte_arr, optimize=True, quality=75, format='JPEG')
                    res_img_base64 = base64.b64encode(byte_arr.getvalue()).decode()
                    resp['image'] = f'data:{mime};base64,{res_img_base64}'

                if len(order) == 1:
                    resp['result'][order[0]] = json.loads(result.result_json)
                else:
                    resp['result'] = json.loads(result.to_json())['result']\
                                     if status != eResultStatus.ERROR else result
                resp['time'] = result.time_stamp.strftime('%Y-%m-%d %H:%M:%S')
                resp['status'] = status.value
                return resp, 200
                # if file_path.endswith("jpg"):
                #     return await send_file(file_path, mimetype='image/jpg')
                # else:
                #     with open(file_path, 'rb') as f:
                #         data = f.read()
                #     return data, 200
            except ValueError as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>/daily_result/<int:result_id>', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly= True)
        async def daily_result(mgr: Account, result_id: int):
            is_text = request.args.get('text') is not None
            try:
                if result_id == 0:
                    result = await mgr.get_latest_daily_result()
                    if result is None:
                        return "无结果", 404
                    resp = mgr.generate_result_info(result)
                    if not is_text:
                        img = await mgr.generate_image(
                            result.result_json if result.result_status == eResultStatus.ERROR
                            else TaskResult().from_json(result.result_json), result.result_status)
                        resp['image'] = mgr.generate_img_base64(img, quality=50)
                else:
                    result = await mgr.get_daily_result_from_id(result_id)
                    if result is None:
                        return "无结果", 404
                    resp = mgr.generate_result_info(result)
                    if not is_text:
                        # return json.loads(result.result_json), 200
                        img = Image.open(await mgr.load_daily_image(result))
                        resp['image'] = mgr.generate_img_base64(img, quality=50)
                return resp, 200
            except ValueError as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>/tools_result', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly= True)
        async def tools_result(mgr: Account):
            try:
                result = await mgr.get_latest_tools_result()
                resp = mgr.generate_result_info(result)
                return resp, 200
            except ValueError as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>/single_result/<string:order>', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly= True)
        async def single_result(mgr: Account, order: str):
            try:
                file_path = await mgr.get_single_result(order)

                if not file_path:
                    return "无结果", 404

                if file_path.endswith("jpg"):
                    return await send_file(file_path, mimetype='image/jpg')
                else:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    return data, 200
            except ValueError as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/account/<string:acc>/query_validate', methods = ['GET'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @HttpServer.wrapaccount(readonly = True)
        async def query_validate(mgr: Account):
            from ..bsdk.validator import validate_dict, ValidateInfo
            if mgr.data_new.account_username not in validate_dict:
                return ValidateInfo(status="empty").to_dict(), 200
            else:
                ret = validate_dict[mgr.data_new.account_username].to_dict()
                del validate_dict[mgr.data_new.account_username]
                return ret, 200

        @self.api.route('/validate', methods = ['POST'])
        async def validate(): # TODO think to check login or not
            data = await request.get_json()
            from ..bsdk.validator import validate_ok_dict
            if 'id' not in data:
                return "incorrect", 403
            id = data['id']
            from ..bsdk.validator import ValidateInfo
            validate_ok_dict[id] = ValidateInfo.from_dict(data)
            return "", 200

        @self.api.route('/modify_profile', methods = ['POST'])
        @rate_limit(1, timedelta(seconds=1))
        @rate_limit(3, timedelta(minutes=1))
        @login_required
        async def modify_profile():
            qid: str = current_user.auth_id
            user = usermgr.qid_map().get(qid, None)
            data = await request.get_json()
            if 'pwd_hash' in data and data['pwd_hash'] != '':
                user.password_hash = data['pwd_hash']
            if 'user_qq' in data:
                if not usermgr.pathsyntax.fullmatch(data['user_qq']):
                    return "user_qq incorrect", 400
                if usermgr.qid_map().get(data['user_qq'], None) is not None:
                    return "user_qq duplication", 400
                user.user_qq = data['user_qq']
                logout_user()
            usermgr.save()
            return "modified", 200

        @self.api.route('/login/qq', methods = ['POST'])
        @rate_limit(1, timedelta(seconds=1))
        @rate_limit(3, timedelta(minutes=1))
        async def login_qq():
            data = await request.get_json()
            qq = data.get('qq', "")
            password = data.get('password', "")

            if not qq or not password:
                return "请输入QQ和密码", 400
            ok = usermgr.validate_password(str(qq), str(password))
            if ok:
                login_user(AuthUser(qq))
                return "欢迎回来，" + qq, 200
            else:
                return "无效的QQ或密码", 400

        @self.api.route('/register', methods = ['POST'])
        @rate_limit(1, timedelta(minutes=1))
        async def register():
            data = await request.get_json()
            qq = data.get('qq', "")
            password = data.get('password', "")
            if not qq or not password:
                return "请输入QQ和密码", 400
            try:
                usermgr.create(str(qq), str(password))
                login_user(AuthUser(qq))
                return "欢迎回来，" + qq, 200
            except UserException as e:
                return str(e), 400
            except Exception as e:
                traceback.print_exc()
                return "服务器发生错误", 500

        @self.api.route('/logout', methods = ['POST'])
        @login_required
        @HttpServer.wrapaccountmgr(readonly = True)
        @rate_limit(1, timedelta(seconds=1))
        async def logout(accountmgr: AccountManager):
            logout_user()
            return "再见, " + accountmgr.qid, 200

        @self.api.route('/super', methods = ['POST'])
        @rate_limit(1, timedelta(minutes=1))
        @HttpServer.check_secret(self.super_secret)
        async def super_test():
            return "correct", 200

        @self.api.route('/super/users', methods = ['POST'])
        @rate_limit(1, timedelta(seconds=3))
        @HttpServer.check_secret(self.super_secret)
        async def super_get_users():
            resp = []
            for item in usermgr.qid_map().values():
                user_info = {'id': item.user_id, 'user_qq': item.user_qq,
                             'register_time': item.register_time.strftime('%Y-%m-%d %H:%M:%S'),
                             'pwd_invalid': item.if_need_reset_pwd}
                resp.append(user_info)
            return resp, 200

        @self.api.route('/super/users/reset_pwd', methods = ['POST'])
        @rate_limit(1, timedelta(seconds=3))
        @HttpServer.check_secret(self.super_secret)
        async def super_reset_usr_pwd():
            data = await request.get_json()
            if 'user_qq' not in data or 'pwd_hash' not in data:
                return "incorrect", 403
            user_qq = data['user_qq']
            users = usermgr.qid_map()
            user = users.get(user_qq, None)
            if user is None:
                return "incorrect", 403
            user.password_hash = data['pwd_hash']
            usermgr.save()
            return "modified", 200

        @self.api.route('/super/users/set_ban', methods = ['POST'])
        @rate_limit(1, timedelta(seconds=3))
        @HttpServer.check_secret(self.super_secret)
        async def super_set_usr_ban():
            data = await request.get_json()
            if 'user_qq' not in data or 'ban' not in data:
                return "incorrect", 403
            user_qq = data['user_qq']
            users = usermgr.qid_map()
            user = users.get(user_qq, None)
            if user is None:
                return "incorrect", 403
            user.if_deleted = bool(data['ban'])
            usermgr.save()
            return "modified", 200

        # frontend
        @self.web.route("/", defaults={"path": ""})
        @self.web.route("/<path:path>")
        async def index(path):
            if os.path.exists(os.path.join(str(self.web.static_folder), path)) and path:
                return await send_from_directory(str(self.web.static_folder), path)
            else:
                return await send_from_directory(str(self.web.static_folder), 'index.html')

    def run_forever(self, loop):
        self.quart.register_blueprint(self.app)
        for rule in self.quart.url_map.iter_rules():
            print(f"{rule.rule}\t{', '.join(rule.methods)}")
        self.quart.run(host=self.host, port=self.port, loop=loop)
