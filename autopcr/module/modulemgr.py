import json
from dataclasses import dataclass
import datetime
from enum import Enum

from PIL import Image
from dataclasses_json import dataclass_json
from typing import List, Dict, Tuple, Union, Any

# from .accountmgr import DailyRecord
from .accdatabase import DbDailyResult, DbModule, DbSingleResult
from ..model.error import *
from ..model.enums import *
from ..db.database import db
from .modulebase import Module, ModuleResult, eResultStatus, eModuleType
from ..util.draw import instance as drawer

import traceback


@dataclass_json
@dataclass
class TaskResult:
    order: List[str] = None
    result: Dict[str, ModuleResult] = None


class ModuleManager:
    _modules: List[type] = []
    _first_init = True

    def __init__(self, config, parent):
        from .modules import daily_modules, tool_modules, cron_modules, hidden_modules
        from .accountmgr import Account
        from .accdatabase import instance as accdb

        self.parent: Account = parent
        self.cron_modules: List[Module] = [m(self) for m in cron_modules]
        self.daily_modules: List[Module] = [m(self) for m in daily_modules]
        self.tool_modules: List[Module] = [m(self) for m in tool_modules]
        self.hidden_modules: List[Module] = [m(self) for m in hidden_modules]
        self.name_to_modules: Dict[str, Module] = {m.key: m for m in (self.daily_modules + self.tool_modules + self.hidden_modules)}
        self.client = self.parent.get_client()
        self._crons = []
        self._load_config(config)
        self._session = parent._session

        try:
            if self._first_init:
                self._init_module_table(accdb.session)
                ModuleManager._first_init = False
        except:
            traceback.print_exc()
            raise

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

    def _init_module_table(self, a_session):
        module_list = [(self.cron_modules, eModuleType.CRON), (self.daily_modules, eModuleType.DAILY),
                       (self.tool_modules, eModuleType.TOOL), (self.hidden_modules, eModuleType.HIDDEN)]

        with a_session:
            exist_modules = {m.module_key: m for m in a_session.query(DbModule).all()}
            for modules, module_type in module_list:
                for module in modules:
                    if module.key in exist_modules:
                        if exist_modules[module.key].module_type != module_type:
                            exist_modules[module.key].module_type = module_type
                        if exist_modules[module.key].module_name != module.name:
                            exist_modules[module.key].module_name = module.name
                        if module_type == eModuleType.HIDDEN:
                            exist_modules[module.key].if_hidden = True
                    else:
                        a_session.add(DbModule(module_key=module.key,module_name=module.name, module_type=module_type,
                                               if_hidden=module_type == eModuleType.HIDDEN))
            a_session.commit()
    
    def _load_config(self, config):
        try:
            self._crons.clear()
            for key, value in config.items():
                self.client.keys[key] = value

            for key in [key for key in config if key.startswith("cron")]:
                enable = config[key]
                if enable:
                    time = config.get("time_" + key, "25:00")
                    if time: # in some case time is None
                        hour, minute = time.split(":")[0:2]
                        is_clan_battle_run = config.get("clanbattle_run_" + key, False)
                        self._crons.append((int(hour), int(minute), is_clan_battle_run))
        except:
            traceback.print_exc()
            raise

    def query_module(self, key: str) -> DbModule:
        return self._session.query(DbModule).filter(DbModule.module_key == key).first()

    @property
    def modules_map(self) -> Dict[str, DbModule]:
        return {m.module_key: m for m in self._session.query(DbModule).all()}

    def is_cron_run(self, nhour, nminute):
        clan_battle_time = db.is_clan_battle_time()
        for hour, minute, is_clan_battle_run in self._crons:
            if hour == nhour and minute == nminute and (is_clan_battle_run or not clan_battle_time):
                return True
        return False
    
    def get_config(self, name, default):
        return self.client.keys.get(name, default)

    def generate_config(self, modules: List[Module]):
        return {
            'config': {**{key: m.get_config(key) for m in modules for key in m.config}, **{m.key: m.get_config(m.key) for m in modules}},
            'order': [m.key for m in modules],
            'info': {m.key: m.generate_info() for m in modules},
        }

    def generate_daily_config(self):
        return self.generate_config(self.cron_modules + self.daily_modules)

    def generate_tools_config(self):
        return self.generate_config(self.tool_modules)

    async def generate_image(self, result: Union[TaskResult, ModuleResult, Any], status: eResultStatus) -> Image.Image:
        if status == eResultStatus.ERROR:
            img = await drawer.draw_msgs([self.parent.qq, self.parent.alias, str(result)])
        elif type(result) is TaskResult:
            img = await drawer.draw_tasks_result(result)
        elif type(result) is ModuleResult:
            img = await drawer.draw_task_result(result)
        else:
            raise ValueError("Unknown result type")
        return img
    
    async def do_daily(self) -> DbDailyResult:
        status = eResultStatus.SUCCESS
        try:
            resp = await self.do_task(self.client.keys, self.daily_modules)
            result = await self.parent.save_daily_result(resp.to_json(), status)
            # img = await drawer.draw_tasks_result(resp)
        except Exception as e:
            traceback.print_exc()
            # img = await drawer.draw_msgs([self.parent.qq, self.parent.alias, str(e)])
            status = eResultStatus.ERROR
            result = await self.parent.save_daily_result(json.dumps({'error': str(e)}), status)
        return result

    async def do_from_key(self, config: dict, key: str) -> DbSingleResult:
        status = eResultStatus.SUCCESS
        try:
            config.update({
                key: True,
                "stamina_relative_not_run": False
            })
            modules = [self.name_to_modules[key]]
            raw_resp = await self.do_task(config, modules)
            return await self.parent.save_single_result(key, result=raw_resp.result[key], status=status)
        except Exception as e:
            traceback.print_exc()
            # img = await drawer.draw_msgs([self.parent.qq, self.parent.alias, str(e)])
            status = eResultStatus.ERROR
            return await self.parent.save_single_result(key, json.dumps({'error': str(e)}), status=status)

    async def do_from_multi_key(self, config: dict, keys: List[str])\
            -> Tuple[Union[str, TaskResult], eResultStatus]:
        status = eResultStatus.SUCCESS
        try:
            config.update({
                "stamina_relative_not_run": False
            })
            config.update({k: True for k in keys})
            modules = [self.name_to_modules[k] for k in keys]
            raw_resp = await self.do_task(config, modules)
            # resp = raw_resp.result[key]
            resp: TaskResult = TaskResult(
                    order=keys,
                    result={k: raw_resp.result[k] for k in keys}
            )
            await self.parent.save_multi_result(resp, time_obj=datetime.datetime.now())
            return resp, status
        except Exception as e:
            traceback.print_exc()
            status = eResultStatus.ERROR
            return json.dumps({'error': str(e)}), status

        # if modules[0].text_result:
        #     file_path = await self.parent.save_single_result_text(key, resp.log)
        # else:
        #     img = await drawer.draw_task_result(resp)
        #     file_path = await self.parent.save_single_result(key, img)

    async def do_task(self, config: dict, modules: List[Module]) -> TaskResult:
        client = self.client
        client.keys["stamina_relative_not_run"] = any(db.is_campaign(campaign) for campaign in client.keys.get("stamina_relative_not_run_campaign_before_one_day", []))

        client.keys.update(config)

        resp: TaskResult = TaskResult(
                order = [m.key for m in modules],
                result = {}
        )
        try:
            await client.login()
            game_data = {
                'game_name': client.name,
                'uid': client.viewer_id,
                'clan_name': '[未加入公会]',
                'clan_id': '[未加入公会]',
                'jewel': client.data.jewel.free_jewel + client.data.jewel.jewel,
                'level': client.data.team_level,
            }
            # self.parent.data.game_name = client.name
            # self.parent.data.uid = client.viewer_id
            clan_info = await client.get_clan_info()
            if clan_info is not None:
                game_data['clan_name'] = clan_info.clan.detail.clan_name
                game_data['clan_id'] = clan_info.clan.detail.clan_id
            self.parent.data_new.game_data = game_data
            # self.parent.data.clan_name, self.parent.data.clan_id = ('[未加入公会]', '[未加入公会]') if clan_info is None else (
            # clan_info.clan.detail.clan_name, clan_info.clan.detail.clan_id)
            time_obj = datetime.datetime.now()
            for module in modules:
                resp.result[module.__class__.__name__] = await module.do_from(client, time_obj)
        except Exception as e:
            traceback.print_exc()
            raise e
        return resp

