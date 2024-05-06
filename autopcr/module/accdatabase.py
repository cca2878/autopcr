import os
# from enum import Enum

from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, JSON, Enum, DateTime, desc, Table, \
    MetaData
from sqlalchemy.orm import declarative_base, Session, relationship

from .modulebase import eResultStatus, eModuleType

from ..constants import CACHE_DIR

# 创建基类
DataDbBase = declarative_base()

daily_result_module = Table('daily_result_module', DataDbBase.metadata,
                            Column('daily_result_id', Integer, ForeignKey('daily_results.daily_result_id')),
                            Column('module_id', Integer, ForeignKey('modules.module_id')))


# 结果表基类
class DbResultBase:
    time_stamp = Column(DateTime, nullable=False)
    result_status = Column(Enum(eResultStatus), nullable=False)
    result_json = Column(String, default='{}', nullable=False)
    image_path = Column(String, nullable=True)


class DbModule(DataDbBase):
    __tablename__ = 'modules'

    module_id = Column(Integer, primary_key=True)
    module_key = Column(String, unique=True, nullable=False)
    module_name = Column(String, nullable=False)
    module_type = Column(Enum(eModuleType), nullable=False)
    if_hidden = Column(Boolean, default=False, nullable=False)

    db_single_result = relationship("DbSingleResult",
                                    foreign_keys='[DbSingleResult.module_id]',
                                    back_populates="db_module")


class DbDailyResult(DbResultBase, DataDbBase):
    """日常任务结果
    result_json: TaskResult.to_json()
    """
    __tablename__ = 'daily_results'

    daily_result_id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.account_id'), nullable=False)

    db_account = relationship("DbAccount", back_populates="db_daily_result")
    db_modules = relationship("DbModule", secondary=daily_result_module, back_populates=None)


class DbSingleResult(DbResultBase, DataDbBase):
    """单次任务结果
    result_json: ModuleResult.to_json()
    """
    __tablename__ = 'single_results'

    single_result_id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.account_id'), nullable=False)
    module_id = Column(Integer, ForeignKey('modules.module_id'), nullable=False)

    db_account = relationship("DbAccount", foreign_keys='[DbSingleResult.account_id]',
                              back_populates="db_single_result")
    db_module = relationship("DbModule", foreign_keys='[DbSingleResult.module_id]', back_populates="db_single_result")


class DbAccount(DataDbBase):
    __tablename__ = 'accounts'

    account_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    account_alias = Column(String, nullable=False)  # 软删除的时候后面加上时间戳
    if_deleted = Column(Boolean, default=False, nullable=False)  # 软删除
    account_username = Column(String, default='', nullable=False)
    account_password = Column(String, default='', nullable=False)
    # 缝合难度有点大，暂时沿用JSON存储
    account_config = Column(JSON, default={}, nullable=False)
    game_data = Column(JSON, default={}, nullable=False)

    db_user = relationship("DbUser", foreign_keys='[DbAccount.user_id]', back_populates="db_account")
    db_as_default_user = relationship("DbUser", foreign_keys='[DbUser.default_account_id]',
                                      back_populates="db_default_account")

    db_daily_result = relationship("DbDailyResult", back_populates="db_account",
                                   foreign_keys='[DbDailyResult.account_id]',
                                   order_by=desc(DbDailyResult.time_stamp))
    db_single_result = relationship("DbSingleResult", back_populates="db_account",
                                    foreign_keys='[DbSingleResult.account_id]',
                                    order_by=desc(DbSingleResult.time_stamp))


class DbUser(DataDbBase):
    __tablename__ = 'users'

    user_id = Column(Integer, primary_key=True)
    user_qq = Column(String, unique=True, nullable=False)
    register_time = Column(DateTime, nullable=False)
    password_hash = Column(String, nullable=False)
    if_need_reset_pwd = Column(Boolean, default=False, nullable=False)
    if_deleted = Column(Boolean, default=False, nullable=False)  # 软删除 战未来
    default_account_id = Column(Integer, ForeignKey('accounts.account_id'))

    db_default_account = relationship("DbAccount",
                                      foreign_keys='[DbUser.default_account_id]',
                                      back_populates="db_as_default_user")
    db_account = relationship("DbAccount", foreign_keys='[DbAccount.user_id]',
                              order_by=DbAccount.account_id.asc(), back_populates="db_user")


class AccDbMgr:
    db_url = f'sqlite:///{os.path.join(CACHE_DIR, "autopcr.sqlite")}'

    def __init__(self):
        self._engine = create_engine(self.db_url, echo=True)
        DataDbBase.metadata.create_all(self._engine)
        # self._init_modules()

    @property
    def session(self) -> Session:
        return Session(self._engine)


instance = AccDbMgr()
