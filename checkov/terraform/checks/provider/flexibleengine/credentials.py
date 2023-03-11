from typing import Dict, List, Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.provider.base_check import BaseProviderCheck


class FlexibleEngineCredentials(BaseProviderCheck):
    def __init__(self) -> None:
        name = "Ensure no hard coded FlexibleEngine password, token, security_token, access_key or secret_key exists in provider"
        id = "CKV_FLEXIBLEENGINE_1"
        supported_provider = ["flexibleengine"]
        categories = [CheckCategories.SECRETS]
        super().__init__(name=name, id=id, categories=categories, supported_provider=supported_provider)

    def scan_provider_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        """
        see: https://registry.terraform.io/providers/FlexibleEngineCloud/flexibleengine/latest/docs#configuration-reference
        """
        result = CheckResult.PASSED
        if conf.get("password"):
            conf[f'{self.id}_secret_1'] = conf.get('password')[0]
            result = CheckResult.FAILED
        if conf.get("token"):
            conf[f'{self.id}_secret_2'] = conf.get('token')[0]
            result = CheckResult.FAILED
        if conf.get("access_key"):
            conf[f'{self.id}_secret_3'] = conf.get('access_key')[0]
            result = CheckResult.FAILED
        if conf.get("secret_key"):
            conf[f'{self.id}_secret_4'] = conf.get('secret_key')[0]
            result = CheckResult.FAILED
        if conf.get("security_token"):
            conf[f'{self.id}_secret_5'] = conf.get('security_token')[0]
            result = CheckResult.FAILED
        return result


check = FlexibleEngineCredentials()
