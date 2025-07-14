from typing import Iterator, Tuple
from ..model.common import eInventoryType
from ..model.custom import ItemType
from . import models

class Reward:
    def __init__(self, reward_type: int, reward_id: int, reward_num: int, odds: int):
        self.reward_item: ItemType = (eInventoryType(reward_type), reward_id)
        self.reward_num = reward_num
        self.odds = odds

def method(cls):
    base_cls = next(base_cls for base_cls in cls.__bases__ if cls.__name__ in base_cls.__name__)
    for method_name, method_obj in cls.__dict__.items():
        if method_name != "__init__" and callable(method_obj):
            setattr(base_cls, method_name, method_obj)
    return cls

@method
class EnemyRewardDatum(models.EnemyRewardDatum):
    def get_rewards(self) -> Iterator[Reward]:
        # Pre-compute rewards to avoid creating objects for zero rewards
        reward_data = [
            (self.reward_type_1, self.reward_id_1, self.reward_num_1, self.odds_1),
            (self.reward_type_2, self.reward_id_2, self.reward_num_2, self.odds_2),
            (self.reward_type_3, self.reward_id_3, self.reward_num_3, self.odds_3),
            (self.reward_type_4, self.reward_id_4, self.reward_num_4, self.odds_4),
            (self.reward_type_5, self.reward_id_5, self.reward_num_5, self.odds_5)
        ]
        for reward_type, reward_id, reward_num, odds in reward_data:
            if reward_id != 0 and reward_num != 0:  # Skip empty rewards
                yield Reward(reward_type, reward_id, reward_num, odds)

@method
class EquipmentCraft(models.EquipmentCraft):
    def get_materials(self) -> Iterator[Tuple[ItemType, int]]:
        # Pre-compute materials to avoid creating tuples for zero materials
        materials_data = [
            (self.condition_equipment_id_1, self.consume_num_1),
            (self.condition_equipment_id_2, self.consume_num_2),
            (self.condition_equipment_id_3, self.consume_num_3),
            (self.condition_equipment_id_4, self.consume_num_4),
            (self.condition_equipment_id_5, self.consume_num_5),
            (self.condition_equipment_id_6, self.consume_num_6),
            (self.condition_equipment_id_7, self.consume_num_7),
            (self.condition_equipment_id_8, self.consume_num_8),
            (self.condition_equipment_id_9, self.consume_num_9),
            (self.condition_equipment_id_10, self.consume_num_10)
        ]
        for equipment_id, consume_num in materials_data:
            if equipment_id != 0 and consume_num != 0:  # Skip empty materials
                yield ((eInventoryType.Equip, equipment_id), consume_num)

@method
class QuestDatum(models.QuestDatum):
    def get_wave_group_ids(self) -> Iterator[int]:
        # Return only non-zero wave group IDs
        wave_groups = [self.wave_group_id_1, self.wave_group_id_2, self.wave_group_id_3]
        for wave_group_id in wave_groups:
            if wave_group_id != 0:
                yield wave_group_id

@method
class WaveGroupDatum(models.WaveGroupDatum):
    def get_drop_reward_ids(self) -> Iterator[int]:
        # Return only non-zero drop reward IDs
        drop_rewards = [
            self.drop_reward_id_1, self.drop_reward_id_2, self.drop_reward_id_3,
            self.drop_reward_id_4, self.drop_reward_id_5
        ]
        for drop_reward_id in drop_rewards:
            if drop_reward_id != 0:
                yield drop_reward_id
