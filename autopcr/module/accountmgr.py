# 名字需要斟酌一下
import base64
import datetime
import hashlib
import io
import json
import os
import re
from asyncio import Lock
# from copy import deepcopy
from dataclasses import dataclass, field, InitVar
from functools import wraps
from typing import Any, Dict, List, Union, Optional

from PIL import Image
# from PIL import Image
from dataclasses_json import dataclass_json
# from sqlalchemy.orm import Session

from .accdatabase import DbAccount
from .accdatabase import instance as accdb, DbUser, DbDailyResult
from .accdatabase import DbSingleResult
from .modulebase import eResultStatus, ModuleResult, eModuleType
from .modulemgr import ModuleManager, TaskResult
from ..constants import CONFIG_PATH, OLD_CONFIG_PATH, RESULT_DIR
from ..core.pcrclient import pcrclient
from ..db.database import db
from sqlalchemy import and_


class AccountException(Exception):
    pass


class UserException(Exception):
    pass


@dataclass_json
@dataclass
class TaskRecord:
    task_id: int = 0
    time: str = "暂无数据"
    time_safe: str = "暂无数据"
    time_obj: InitVar[datetime.datetime] = None
    status: eResultStatus = eResultStatus.SKIP

    def __post_init__(self, time_obj: datetime.datetime = None):
        if time_obj is not None:
            self.time = time_obj.strftime('%Y-%m-%d %H:%M:%S')
            self.time_safe = db.format_time_safe(time_obj)


@dataclass_json
@dataclass
class AccountData:
    """弃用"""
    username: str = ""
    password: str = ""
    game_name: str = ""
    uid: str = ""
    clan_name: str = ""
    clan_id: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    daily_result: List[TaskRecord] = field(default_factory=list)


@dataclass_json
@dataclass
class UserData:
    password: str = ""
    default_account: str = ""


class Account(ModuleManager):
    def __init__(self, parent: 'AccountManager', qid: str, account: str, readonly: bool = False):
        if not account in parent.account_lock:
            parent.account_lock[account] = Lock()
        self._lck = parent.account_lock[account]
        # self._filename = parent.path(account)
        self._session = accdb.session
        self._parent = parent
        self.readonly = readonly
        self.id = hashlib.md5(account.encode('utf-8')).hexdigest()
        self.qq = qid
        self.alias = account

        if self.readonly:
            def raise_exception():
                raise Exception("Cannot commit in readonly mode")

            self._session.commit = raise_exception
        # if not os.path.exists(self._filename):
        #     raise AccountException("账号不存在")
        #
        # with open(self._filename, 'r') as f:
        #     self.data: AccountData = AccountData.from_json(f.read())
        #     self.old_data: AccountData = deepcopy(self.data)

        user: DbUser = self._session.query(DbUser).filter(DbUser.user_qq == qid).first()
        if user is None:
            raise UserException("用户不存在")
        self.data_new: DbAccount = self._session.query(DbAccount).filter(
            and_(DbAccount.account_alias == account, DbAccount.user_id == user.user_id, DbAccount.if_deleted == False)
        ).first()
        if self.data_new is None:
            raise AccountException("账号不存在")

        # self.token = f"{self.qq}_{self.alias}"
        super().__init__(self.data_new.account_config, self)

    async def __aenter__(self):
        if not self.readonly:
            await self._lck.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.readonly:
            # if self.data != self.old_data:
            #     await self.save_data()
            self._session.commit()
            self._lck.release()
        self._session.close()

    async def save_data(self):  # 弃用
        pass
        # with open(self._filename, 'w') as f:
        #     f.write(self.data.to_json())

    # @auto_commit
    def update_config(self, config: Dict[str, Any]):
        new_config = self.data_new.account_config.copy()
        new_config.update(config)
        self.data_new.account_config = new_config

    async def load_daily_image(self, result: DbDailyResult) -> str:
        if not result.image_path or not os.path.exists(result.image_path):
            file_name = f'daily_{result.daily_result_id}_{db.format_time_safe(result.time_stamp)}.jpg'
            img = await self.generate_image(
                result.result_json if result.result_status == eResultStatus.ERROR
                else TaskResult().from_json(result.result_json), result.result_status)

            file_path = os.path.join(self.qq, self.alias, 'daily')
            if not os.path.exists(os.path.join(RESULT_DIR, file_path)):
                os.makedirs(os.path.join(RESULT_DIR, file_path))
            img.save(os.path.join(RESULT_DIR, file_path, file_name), optimize=True, quality=75)
            result.image_path = os.path.join(file_path, file_name)
        return os.path.join(RESULT_DIR, result.image_path)

    async def load_single_image(self, result: DbSingleResult) -> str:
        if not result.image_path or not os.path.exists(result.image_path):
            m_name = result.db_module.module_key
            file_name = f'single_{result.single_result_id}_{m_name}_{db.format_time_safe(result.time_stamp)}.jpg'
            img = await self.generate_image(status=result.result_status,
                                            result=ModuleResult.from_json(result.result_json))
            file_path = os.path.join(self.qq, self.alias, 'single')
            if not os.path.exists(os.path.join(RESULT_DIR, file_path)):
                os.makedirs(os.path.join(RESULT_DIR, file_path))
            img.save(os.path.join(RESULT_DIR, file_path, file_name), optimize=True, quality=75, format='JPEG')
            result.image_path = os.path.join(file_path, file_name)
        return os.path.join(RESULT_DIR, result.image_path)

    async def save_daily_result(self, result: str, status: eResultStatus) -> DbDailyResult:
        """已重写"""
        # now = datetime.datetime.now()
        # time_safe = db.format_time_safe(now)
        # result_dir = os.path.join(RESULT_DIR, self.qq, self.alias, 'daily', f"{self.token}_{time_safe}")
        # file = os.path.join(result_dir, 'result.json')
        # result.save(file, optimize=True, quality=75)
        # result_json = json.dumps({'is_error': is_error, 'data': result})
        # item = DailyResult.create(result_dir = result_dir, result=result, time = db.format_time(now),
        # time_safe=time_safe, status = status)
        item = DbDailyResult(time_stamp=datetime.datetime.now(), result_status=status, result_json=result)
        for m in self.modules_map:
            item.db_modules.append(self.modules_map[m])
        self.data_new.db_daily_result.insert(0, item)
        # item = create_daily_result([self.qq, self.alias], result, datetime.datetime.now(), status)
        # old_list = self.data.daily_result
        self._session.commit()
        if len(self.data_new.db_daily_result) >= 4:
            for i in range(3, len(self.data_new.db_daily_result)):
                # Delete the last result
                self.delete_result(self.data_new.db_daily_result[i])

        #     if os.path.exists(old_list[-1].result_dir):
        #         os.remove(old_list[-1].result_dir)
        #     old_list.pop()
        # self.data.daily_result = [item] + old_list
        return item

    async def save_multi_result(self, result: TaskResult, time_obj: datetime = None):
        time_obj = datetime.datetime.now() if time_obj is None else time_obj
        dm_map = self.modules_map
        for m in result.order:
            await self.save_single_result(m, result.result[m], status=result.result[m].status,
                                          time_obj=time_obj, modules_map=dm_map)

    async def save_single_result(self, key: str, result: Union[ModuleResult, str], status: eResultStatus,
                                 time_obj=None, modules_map=None) -> DbSingleResult:
        """已重写"""
        # file = os.path.join(RESULT_DIR, f"{self.token}_{module}.jpg")
        # result.save(file, optimize=True, quality=75)
        # item = DbSingleResult(time_stamp=datetime.datetime.now(), module_id=module_id, result_json=result)
        # self.data_new.db_single_result.append(item)
        modules_map = modules_map or self.modules_map
        time_obj = time_obj or datetime.datetime.now()
        parent_m = modules_map[key]
        new_res = DbSingleResult(time_stamp=time_obj, result_status=status, module_id=parent_m.module_id,
                                 result_json=result if status == eResultStatus.ERROR else result.to_json())
        self.data_new.db_single_result.insert(0, new_res)
        # parent_m.db_single_result.append(new_res)
        self._session.commit()

        results = [r for r in self.data_new.db_single_result if r.module_id == parent_m.module_id]
        if len(results) >= 4:
            for i in range(3, len(results)):
                # Delete the last result
                self.delete_result(results[i])

        return new_res

    def delete_result(self, result: Union[DbDailyResult, DbSingleResult]):
        self._session.delete(result)
        if result.image_path:
            img_path = os.path.join(RESULT_DIR, result.image_path)
            if os.path.exists(img_path):
                os.remove(img_path)

    async def get_daily_result_img_from_index(self, id_: int = 0) -> str:
        """已重写"""
        result = self.data_new.db_daily_result
        if len(result) > id_:
            return await self.load_daily_image(result[id_])
        else:
            return ""

    async def get_daily_result_from_id(self, result_id: int) -> Optional[DbDailyResult]:
        """已重写"""
        # ret = [daily_result.path for daily_result in self.data.daily_result if safe_time == daily_result.time_safe]
        # results_time = {db.format_time_safe(item.time_stamp): item for item in self.data_new.db_daily_result}
        for daily_result in self.data_new.db_daily_result:
            if daily_result.daily_result_id == result_id:
                return daily_result
        return None
        # if ret:
        #     return ret[0]
        # else:
        #     return ""
        # return results_time.get(safe_time, None)

    async def get_latest_daily_result(self) -> Optional[DbDailyResult]:
        """
        获取最新的日常结果
        """
        # Get the latest valid DailyResult
        latest_daily_result = self.data_new.db_daily_result[0] if self.data_new.db_daily_result else None
        latest_single_time = self.data_new.db_single_result[0].time_stamp if self.data_new.db_single_result else None

        if not latest_daily_result:
            return None
        if latest_daily_result.result_status == eResultStatus.ERROR or latest_single_time is None:
            return latest_daily_result
        if latest_daily_result.time_stamp > latest_single_time:
            return latest_daily_result

        result_obj = TaskResult().from_json(latest_daily_result.result_json)

        # 找到最新的结果，性能方面可能有问题，猪鼻不会算法
        for module in latest_daily_result.db_modules:
            time_stamp = datetime.datetime.fromtimestamp(0)
            for sr in self.data_new.db_single_result:
                if sr.module_id == module.module_id and sr.time_stamp > latest_daily_result.time_stamp and sr.time_stamp > time_stamp:
                    time_stamp = sr.time_stamp
                    if sr.result_status == eResultStatus.ERROR:
                        result_obj.result[module.module_key] = sr.result_json
                    else:
                        result_obj.result[module.module_key] = ModuleResult.from_json(sr.result_json)

        new_daily_result = DbDailyResult(
            time_stamp=datetime.datetime.now(),
            result_status=eResultStatus.SUCCESS,
            result_json=result_obj.to_json()
        )

        return new_daily_result

    async def get_latest_tools_result(self):
        """
        获取工具历史结果
        这玩意没有全部执行，不需要时间判断
        """
        tool_modules = [module for module in self.modules_map.values() if module.module_type == eModuleType.TOOL]
        result_obj = TaskResult(order=[], result={})
        for module in tool_modules:
            time_stamp = datetime.datetime.fromtimestamp(0)
            for sr in self.data_new.db_single_result:
                if sr.module_id == module.module_id and sr.time_stamp > time_stamp:
                    time_stamp = sr.time_stamp
                    if sr.result_status == eResultStatus.ERROR:
                        result_obj.result[module.module_key] = sr.result_json
                    else:
                        result_obj.result[module.module_key] = ModuleResult.from_json(sr.result_json)

        tools_result = DbDailyResult(
            time_stamp=datetime.datetime.now(),
            result_status=eResultStatus.SUCCESS,
            result_json=result_obj.to_json()
        )

        return tools_result

    async def get_single_result(self, module_name, time_safe: str = None) -> Optional[DbSingleResult]:
        """已重写"""
        for result in self.data_new.db_single_result:
            if (result.module.module_key == module_name and
                    (time_safe is None or db.format_time_safe(result.time_stamp) == time_safe)):
                return result
        return None

        # file = os.path.join(RESULT_DIR, f"{self.token}_{module_name}.jpg")
        # file2 = os.path.join(RESULT_DIR, f"{self.token}_{module_name}.txt")
        # if os.path.exists(file):
        #     return file
        # elif os.path.exists(file2):
        #     return file2
        # else:
        #     return ""

    def get_last_daily_clean(self) -> TaskRecord:
        """弃用"""
        if self.data_new.db_daily_result:
            result = self.data_new.db_daily_result[0]
            return TaskRecord(time=result.time_stamp.strftime('%Y-%m-%d %H:%M:%S'),
                              time_safe=db.format_time_safe(result.time_stamp),
                              status=result.result_status)

        else:
            return TaskRecord()

    def get_all_daily_clean(self):
        return [TaskRecord(time_obj=result.time_stamp, task_id=result.daily_result_id, status=result.result_status)
                for result in self.data_new.db_daily_result]

    def get_client(self) -> pcrclient:
        return self.get_android_client()

    def get_ios_client(self) -> pcrclient:  # Header TODO
        client = pcrclient({
            'account': self.data_new.account_username,
            'password': self.data_new.account_password,
            'channel': 1000,
            'platform': 1
        })
        return client

    def get_android_client(self) -> pcrclient:
        client = pcrclient({
            'account': self.data_new.account_username,
            'password': self.data_new.account_password,
            'channel': 1,
            'platform': 2
        })
        return client

    def generate_info(self):
        def _mask_str(mask_str: str) -> str:
            if not isinstance(mask_str, str):
                raise ValueError("Input must be a string")
            elif not mask_str:
                return ""
            else:
                return "*" * 7 + mask_str[-1]

        info = {
            'alias': self.alias,
            'username': self.data_new.account_username,
            'password': 8 * "*" if self.data_new.account_password else "",
            'game_info': self.data_new.game_data,
            'area': [{"key": 'daily', "name": "日常"}, {"key": 'tools', "name": "工具"}]
        }
        if self.data_new.db_daily_result:
            record = TaskRecord(status=self.data_new.db_daily_result[0].result_status.value,
                                time_obj=self.data_new.db_daily_result[0].time_stamp,
                                task_id=self.data_new.db_daily_result[0].daily_result_id)
            info['last_daily_info'] = json.loads(record.to_json())
        else:
            info['last_daily_info'] = json.loads(TaskRecord().to_json())
        if self.data_new.db_single_result:
            record = TaskRecord(status=self.data_new.db_single_result[0].result_status.value,
                                time_obj=self.data_new.db_single_result[0].time_stamp,
                                task_id=self.data_new.db_single_result[0].single_result_id)
            info['last_task_info'] = json.loads(record.to_json())
            info['last_task_info']['name'] = self.data_new.db_single_result[0].db_module.module_name
        else:
            info['last_task_info'] = json.loads(TaskRecord().to_json())
            info['last_task_info']['name'] = None
        return info

    def generate_daily_info(self):
        info = super().generate_daily_config()
        return info

    def generate_result_info(self, result_item: DbDailyResult):
        resp = {
            "status": result_item.result_status.value,
            "time": result_item.time_stamp.strftime('%Y-%m-%d %H:%M:%S'),
            "order": json.loads(result_item.result_json)['order']
            if result_item.result_status != eResultStatus.ERROR else [],
            "result": json.loads(result_item.result_json)['result']
            if result_item.result_status != eResultStatus.ERROR else result_item.result_json,
            'image': None
        }
        return resp

    def generate_img_base64(self, res_img: Image.Image, quality: int = 75) -> str:
        mime = 'image/jpeg'
        byte_arr = io.BytesIO()
        res_img.save(byte_arr, optimize=True, quality=quality, format='JPEG')
        res_img_base64 = base64.b64encode(byte_arr.getvalue()).decode()
        return f'data:{mime};base64,{res_img_base64}'

    def generate_tools_info(self):
        info = super().generate_tools_config()
        return info

    def delete(self):
        self._parent.delete(self.alias)


class AccountManager:
    pathsyntax = re.compile(r'[^\\|?*/]{1,32}')

    def __init__(self, parent: 'UserManager', qid: str, readonly: bool = False):
        if qid not in parent.user_lock:
            parent.user_lock[qid] = Lock()
        self._lck = parent.user_lock[qid]
        self.qid = qid
        # self.root = parent.qid_path(qid)
        self._parent = parent
        self.readonly = readonly

        self._session = accdb.session
        self.secret_new: DbUser = self._session.query(DbUser).filter(DbUser.user_qq == qid).first()
        if self.secret_new is None:
            raise UserException("账号不存在")
        #
        # with open(self.root + '/secret', 'r') as f:
        #     self.secret: UserData = UserData.from_json(f.read())
        #     self.old_secret = deepcopy(self.secret)

    async def __aenter__(self):
        if not self.readonly:
            await self._lck.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.readonly:
            self._session.commit()

            # if self.secret != self.old_secret:
            #     self.save_secret()
            self._lck.release()
        self._session.close()

    def check_account(func):
        """
        装饰器：检查账户是否合法、是否归属于当前用户、是否已经标记删除
        需要方法的第一个参数为账户名
        """

        @wraps(func)
        def wrapper(self, account, *args, **kwargs):
            if not AccountManager.pathsyntax.fullmatch(account):
                raise AccountException('非法账户名')
            if account not in self.accounts_map() or self.query_account(account).if_deleted:
                raise AccountException(f"非法账户请求：{account}")

            return func(self, account, *args, **kwargs)

        return wrapper

    @property
    def account_lock(self) -> Dict[str, Lock]:
        if self.qid not in self._parent.account_lock:
            self._parent.account_lock[self.qid] = {}
        return self._parent.account_lock[self.qid]

    def query_account(self, account: str) -> Optional[DbAccount]:
        """
        根据alias在用户的账号列表中查询账户
        用这玩意的方法，记得加上 check_account 装饰器
        """
        return self.accounts_map().get(account, None)

    def create_account(self, account: str) -> Account:
        if not AccountManager.pathsyntax.fullmatch(account):
            raise AccountException(f'非法账号名{account}')
        if account in self.accounts_map():
            raise AccountException('名称重复')

        new_acc = DbAccount(account_alias=account)
        self.secret_new.db_account.append(new_acc)
        self._session.commit()
        if len(self.accounts_map()) == 1:
            self.secret_new.default_account_id = new_acc.account_id
        self._session.commit()
        # with open(self.path(account), 'w') as f:
        #     f.write(AccountData().to_json())
        return self.load(account)

    def save_secret(self):  # 弃用
        pass
        # with open(self.root + '/secret', 'w') as f:
        #     f.write(self.secret.to_json())

    @check_account
    def set_default_account(self, account: str):
        self.secret_new.default_account_id = self.query_account(account).account_id

    def validate_password(self, password_hash: str) -> bool:
        return self.secret_new.password_hash == password_hash

    def load(self, account: str = "", readonly=False) -> Account:
        if not AccountManager.pathsyntax.fullmatch(account):
            raise AccountException(f'非法账户名{account}')
        if account not in self.accounts_map():
            raise AccountException(f"非法账户请求：{account}")
        acc = account or self.default_account or (
            list(self.accounts_map().keys())[0] if len(self.accounts_map()) == 1 else None)
        if not acc:
            raise AccountException('No default account')
        return Account(self, self.qid, acc, readonly)
        # acc = account
        # if not acc:
        #     acc = self.secret.default_account
        # if not acc and len(list(self.accounts())) == 1:
        #     acc = list(self.accounts())[0]
        # if not acc:
        #     raise AccountException('No default account')
        # return Account(self, self.qid, acc, readonly)

    # def path(self, account: str) -> str:  # 弃用
    #     return os.path.join(self.root, account + '.json')

    @check_account
    def delete(self, account: str):
        """软删除"""
        db_acc_obj = self.query_account(account)

        if len(self.accounts_map()) == 1:
            self.secret_new.default_account_id = None
        elif db_acc_obj.account_id == self.secret_new.default_account_id:
            next_acc = next((acc.account_id for acc in self.secret_new.db_account if
                             acc.account_id != db_acc_obj.account_id and not acc.if_deleted), None)
            self.secret_new.default_account_id = next_acc

        db_acc_obj.if_deleted = True
        db_acc_obj.account_alias += f"_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        # self._session.delete(self.query_account(account))
        # os.remove(self.path(account))

    @property
    def default_account(self) -> str:
        default_acc = next((acc for acc in self.secret_new.db_account
                            if acc.account_id == self.secret_new.default_account_id), None)
        return default_acc.account_alias if default_acc else None
        # return self.secret.default_account

    def accounts_map(self):
        # for fn in os.listdir(self.root):
        #     if fn.endswith('.json'):
        #         yield fn[:-5]
        """
        查询 DbAccount 表并过滤出与当前用户 user_id 匹配的记录
        从每个匹配的记录中提取 account_alias 并返回
        """
        return {record.account_alias: record for record in self.secret_new.db_account if not record.if_deleted}

    async def generate_info(self):
        """已重写"""
        accounts = []
        for account in self.accounts_map():
            async with self.load(account, readonly=True) as acc:
                records = acc.get_all_daily_clean()
                accounts.append({
                    'name': account,
                    'daily_clean_time': json.loads(records[0].to_json()) if records else [],
                    'daily_clean_time_list': [json.loads(r.to_json()) for r in records] if records else [],
                })
        return {
            'qq': self.qid,
            'default_account': self.default_account,
            'accounts': accounts
        }


class UserManager:
    pathsyntax = re.compile(r'\d{5,12}')

    def __init__(self, root: str):
        self.root = root
        self.user_lock: Dict[str, Lock] = {}
        self.account_lock: Dict[str, Dict[str, Lock]] = {}
        self._session = accdb.session

    def check_qid(func):
        """
        装饰器：检查qid是否合法、是否已经标记删除
        需要方法的第一个参数为qid
        """

        @wraps(func)
        def wrapper(self, qid, *args, **kwargs):
            if not UserManager.pathsyntax.fullmatch(qid) or qid not in self.qid_map():
                raise AccountException('无效的QQ号')
            return func(self, qid, *args, **kwargs)

        return wrapper

    def validate_password(self, qid: str, pwd_hash: str) -> bool:
        try:
            if qid not in self.qid_map():
                return False
            return self.load(qid).validate_password(pwd_hash)
        except Exception as e:
            print(e)
            return False

    # def qid_path(self, qid: str) -> str:
    #     return os.path.join(self.root, qid)

    def create(self, qid: str, pwd_hash: str) -> AccountManager:
        if not UserManager.pathsyntax.fullmatch(qid):
            raise UserException('无效的QQ号')
        if qid in self.qid_map():
            raise UserException('该QQ号用户已存在')
        # os.makedirs(self.qid_path(qid))
        # with open(self.qid_path(qid) + '/secret', 'w') as f:
        #     f.write(UserData(password=password_hash).to_json())

        new_user = DbUser(user_qq=qid, password_hash=pwd_hash, register_time=datetime.datetime.now())
        self._session.add(new_user)
        self._session.commit()
        self.shift_old_accounts(qid)
        return AccountManager(self, qid)

    def save(self):
        self._session.commit()

    def shift_old_accounts(self, qid: str):  # TODO: 改数据库工程量大，编写独立脚本迁移
        pass
        # import glob
        # for config in glob.glob(os.path.join(OLD_CONFIG_PATH, "*.json")):
        #     with open(config, 'r') as f:
        #         data = json.load(f)
        #         if str(data.get('qq', '')) == qid:
        #             os.rename(config, os.path.join(self.qid_path(qid), data['alian'] + '.json'))

    @check_qid
    def load(self, qid: str, readonly: bool = False) -> AccountManager:
        return AccountManager(self, qid, readonly)

    @check_qid
    def delete(self, qid: str, account: str = ""):  # TODO: 数据库标记删除。暂时没有启用，以后再写
        pass
        # if not UserManager.pathsyntax.fullmatch(qid) or qid not in self.qids():
        #     raise AccountException('无效的QQ号')
        # if account:
        #     self.load(qid).delete(account)
        # else:
        #     os.removedirs(self.qid_path(qid))

    def qid_map(self) -> dict[str, DbUser]:
        # for fn in os.listdir(self.root):
        #     if fn.isdigit() and os.path.isdir(os.path.join(self.root, fn)):
        #         yield fn
        return {item.user_qq: item for item in self._session.query(DbUser).filter(DbUser.if_deleted == False).all()}
        # for record in self._session.query(DbUser).filter(not DbUser.if_deleted).all():
        #     yield record.user_qq


instance = UserManager(os.path.join(CONFIG_PATH))
