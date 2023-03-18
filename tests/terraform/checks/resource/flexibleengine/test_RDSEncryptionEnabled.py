import unittest

import hcl2

from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.flexibleengine.RDSEncryptionEnabled import check


class TestRDSEncryptionEnabled(unittest.TestCase):
    
    def test_failure_rds_instance_not_encrypted_volume(self):
        hcl_res = hcl2.loads("""
          resource "flexibleengine_rds_instance_v3" "instance" {
            name              = "terraform_test_rds_instance"
            flavor            = "rds.pg.s3.medium.4"
            availability_zone = [var.primary_az]
            security_group_id = flexibleengine_networking_secgroup_v2.example_secgroup.id
            vpc_id            = flexibleengine_vpc_v1.example_vpc.id
            subnet_id         = flexibleengine_vpc_subnet_v1.example_subnet.id

            db {
              type     = "PostgreSQL"
              version  = "11"
              password = var.db_password
              port     = "8635"
            }
            volume {
              type               = "COMMON"
              size               = 100
            }
            backup_strategy {
              start_time = "08:00-09:00"
              keep_days  = 1
            }
          }
          resource "flexibleengine_vpc_v1" "example_vpc" {
            name = "example-vpc"
            cidr = "192.168.0.0/16"
          }

          resource "flexibleengine_vpc_subnet_v1" "example_subnet" {
            name       = "example-vpc-subnet"
            cidr       = "192.168.0.0/24"
            gateway_ip = "192.168.0.1"
            vpc_id     = flexibleengine_vpc_v1.example_vpc.id
          }

          resource "flexibleengine_networking_secgroup_v2" "example_secgroup" {
            name        = "terraform_test_security_group"
            description = "terraform security group acceptance test"
          }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_rds_instance_v3']['instance']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_pass_rds_instance_encrypted_volume(self):
        hcl_res = hcl2.loads("""
          resource "flexibleengine_rds_instance_v3" "instance" {
            name              = "terraform_test_rds_instance"
            flavor            = "rds.pg.s3.medium.4"
            availability_zone = [var.primary_az]
            security_group_id = flexibleengine_networking_secgroup_v2.example_secgroup.id
            vpc_id            = flexibleengine_vpc_v1.example_vpc.id
            subnet_id         = flexibleengine_vpc_subnet_v1.example_subnet.id

            db {
              type     = "PostgreSQL"
              version  = "11"
              password = var.db_password
              port     = "8635"
            }
            volume {
              disk_encryption_id = flexibleengine_kms_key_v1.key.id
              type               = "COMMON"
              size               = 100
            }
            backup_strategy {
              start_time = "08:00-09:00"
              keep_days  = 1
            }
          }
          resource "flexibleengine_kms_key_v1" "key" {
            key_alias       = "key_1"
            key_description = "first test key"
            is_enabled      = true
          }

          resource "flexibleengine_vpc_v1" "example_vpc" {
            name = "example-vpc"
            cidr = "192.168.0.0/16"
          }

          resource "flexibleengine_vpc_subnet_v1" "example_subnet" {
            name       = "example-vpc-subnet"
            cidr       = "192.168.0.0/24"
            gateway_ip = "192.168.0.1"
            vpc_id     = flexibleengine_vpc_v1.example_vpc.id
          }

          resource "flexibleengine_networking_secgroup_v2" "example_secgroup" {
            name        = "terraform_test_security_group"
            description = "terraform security group acceptance test"
          }
        """)

        resource_conf = hcl_res['resource'][0]['flexibleengine_rds_instance_v3']['instance']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)


if __name__ == '__main__':
    unittest.main()
