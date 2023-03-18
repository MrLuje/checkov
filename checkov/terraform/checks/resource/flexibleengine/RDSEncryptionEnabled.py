from typing import List
from checkov.common.models.consts import ANY_VALUE

from checkov.common.models.enums import CheckCategories
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck

class RDSEncryptionEnabled(BaseResourceValueCheck):
    def __init__(self) -> None:
        name = "Ensure that RDS server enables disk encryption"
        id = "CKV_FLEXIBLEENGINE_6"
        supported_resources = ("flexibleengine_rds_instance_v3",)
        categories = (CheckCategories.ENCRYPTION,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self) -> str:
        return "volume/[0]/disk_encryption_id"

    def get_expected_values(self):
        return [ANY_VALUE]


check = RDSEncryptionEnabled()
