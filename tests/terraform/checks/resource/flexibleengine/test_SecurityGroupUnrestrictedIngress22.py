import unittest

import hcl2

from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.flexibleengine.SecurityGroupUnrestrictedIngress22 import check


class TestSecurityGroupUnrestrictedIngress22(unittest.TestCase):

    def test_failure_networking_secgroup(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_v2" "secgroup_1" {
          name        = "secgroup_1"
          description = "My neutron security group"
        }
        
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 22
          port_range_max    = 22
          remote_ip_prefix  = "0.0.0.0/0"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_v2']['secgroup_1']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

        resource_conf = hcl_res['resource'][1]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_failure_networking_secgroup_port_range(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 1
          port_range_max    = 65535
          remote_ip_prefix  = "0.0.0.0/0"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_pass_networking_secgroup(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 22
          port_range_max    = 22
          remote_ip_prefix  = "192.168.0.0/16"
          security_group_id = "${flexibleengine_networking_secgroup_v2.secgroup_1.id}"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_pass_networking_secgroup_icmp(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "icmp"
          port_range_min    = 22
          port_range_max    = 22
          remote_ip_prefix  = "0.0.0.0/0"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_unknown_networking_secgroup_egress(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "egress" {
          direction         = "egress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 22
          port_range_max    = 22
          remote_ip_prefix  = "0.0.0.0/0"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['egress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.UNKNOWN, scan_result)

    def test_pass_networking_secgroup_source_sg(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 22
          port_range_max    = 22
          security_group_id = "${flexibleengine_networking_secgroup_v2.secgroup_1.id}"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_pass_networking_secgroup_different_port(self):
        hcl_res = hcl2.loads("""
        resource "flexibleengine_networking_secgroup_rule_v2" "ingress" {
          direction         = "ingress"
          ethertype         = "IPv4"
          protocol          = "tcp"
          port_range_min    = 222
          port_range_max    = 222
          remote_ip_prefix  = "0.0.0.0/0"
        }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_networking_secgroup_rule_v2']['ingress']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)


if __name__ == '__main__':
    unittest.main()