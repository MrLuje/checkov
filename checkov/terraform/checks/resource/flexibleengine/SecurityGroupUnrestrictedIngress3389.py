from checkov.terraform.checks.resource.flexibleengine.AbsSecurityGroupUnrestrictedIngress import AbsSecurityGroupUnrestrictedIngress


class SecurityGroupUnrestrictedIngress3389(AbsSecurityGroupUnrestrictedIngress):
    def __init__(self):
        super().__init__(check_id="CKV_FLEXIBLEENGINE_3", port=3389)


check = SecurityGroupUnrestrictedIngress3389()
