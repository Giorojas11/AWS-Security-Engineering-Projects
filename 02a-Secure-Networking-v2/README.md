# AWS Secure Networking v2

This iteration of the secure networking project represents an evolution of my previous <a href="https://github.com/Giorojas11/AWS-Projects/tree/main/02-Secure-Networking"> secure networking project</a>. The original established foundational, secure network architecture with multiple VPCs, routing, NACLs, and segmentation. This version focuses on high availability, fault tolerance, and long-term scalability aligned with production-grade AWS environments. 

This is a major refinement of my previous my network architecture, along with a refactoring of my Terraform code that will be used in future cloud security projects.

## Table of Contents
1. [Network Diagram](#network-diagram)
   - [Before](#before)
   - [After](#after)
2. [Key Enhancments](#key-enhancements)
   - [Multi-AZ Deployment](#1-multi-az-deployment)
   - [Inclusion of the Isolated Subnet](#2-inclusion-of-the-isolated-subnet)
   - [Explicit Routing, NACLs, & Security Groups](#3-explicit-routing-nacls--security-groups)
   - [Centralized Network Visibility & Logging](#4-centralized-network-visibility--logging)
   - [Scalable Terraform Naming & Structure](#5-scalable-terraform-naming--structure)
   - [Security-Ready Archtitecture](#6-security-ready-architecture)
3. [Design Decisions](#design-decisions)
   - [High Availability as a Baseline](#high-availability-as-a-baseline)
   - [Defense-in-Depth & Least-Privilege through Segmentation](#defense-in-depth--least-privilege-through-segmentation)
   - [Avoiding Cross-AZ Dependency](#avoiding-cross-az-dependency)
   - [Observability](#observability)
   - [Terraform Built for Scalability & Consistency](#terraform-built-for-scalability--consistency)

## Network Diagram
  ### Before
![AWS Network Diagram](https://github.com/user-attachments/assets/c4189724-cdc8-4ba0-9eb4-a79844976b83)


  ### After
![AWS Network Diagram(1)](https://github.com/user-attachments/assets/fd661f42-03b1-48b9-b150-0ebfda5db86d)


   
## Key Enhancements
### 1. Multi-AZ Deployment
Subnets are now provisioned across multiple Availability Zones to ensure high availability and tolerance for AZ-level outages. This significantly improves the reliability of the architecture and shifts away from the original single-AZ design.
```
resource "aws_vpc" "prod_use1_vpc" {
    cidr_block = var.prod_vpc_cidr_block

    enable_dns_support   = true
    enable_dns_hostnames = true
    
    tags = {
        Name = "prod-use1-vpc"
    }
}

resource "aws_internet_gateway" "prod_use1_igw" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    tags = {
        Name = "prod-use1-igw"
    }
}

resource "aws_vpc" "sec_use1_vpc" {
    cidr_block = var.sec_vpc_cidr_block

    enable_dns_support   = true
    enable_dns_hostnames = true
    
    tags = {
        Name = "sec-use1-vpc"
    }
}

resource "aws_internet_gateway" "sec_use1_igw" {
    vpc_id = aws_vpc.sec_use1_vpc.id

    tags = {
        Name = "sec-use1-igw"
    }
}

resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id       = aws_vpc.prod_use1_vpc.id
  service_name = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.prod_use1_rt_public_a.id,
    aws_route_table.prod_use1_rt_private_a.id,
    aws_route_table.prod_use1_rt_isolated_a.id,
    aws_route_table.prod_use1_rt_public_b.id,
    aws_route_table.prod_use1_rt_private_b.id,
    aws_route_table.prod_use1_rt_isolated_b.id
   ]

  tags = {
    Environment = "prod"
    Name = "prod-use1-s3-endpoint"
  }
}
```


<img width="1156" height="776" alt="prod-vpc-rt-igw-nat-vpce" src="https://github.com/user-attachments/assets/aa82859e-2deb-4f5d-a20c-feb0c93ea68b" />


<img width="1473" height="684" alt="sec-vpc" src="https://github.com/user-attachments/assets/641c2e17-1e5d-48f6-895a-da954d834633" />



### 2. Inclusion of the Isolated Subnet
The architecure now includes:
  - Public Subnets (Internet Access)
  - Private Subnets (Egress internet access using NAT)
  - Isolated Subnets (NO INTERNET ACCESS) - For future sensitive data and/or tooling
```
#===========================================
# 10.0.0.0/16 - US-EAST-1A
#===========================================
resource "aws_subnet" "prod_use1_public_a" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.0.0/24"
    map_public_ip_on_launch  = true
    availability_zone        = "us-east-1a"

    tags = {
        Name = "prod-use1-public-a"
    }
}

resource "aws_subnet" "prod_use1_private_a" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.1.0/24"
    map_public_ip_on_launch  = false
    availability_zone        = "us-east-1a"

    tags = {
        Name = "prod-use1-private-a"
    }
}

resource "aws_subnet" "prod_use1_isolated_a" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.2.0/24"
    map_public_ip_on_launch  = false
    availability_zone        = "us-east-1a"

    tags = {
        Name = "prod-use1-isolated-a"
    }
}
#===========================================
# 10.0.0.0/16 - US-EAST-1B
#===========================================
resource "aws_subnet" "prod_use1_public_b" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.3.0/24"
    map_public_ip_on_launch  = true
    availability_zone        = "us-east-1b"

    tags = {
        Name = "prod-use1-public-b"
    }
}

resource "aws_subnet" "prod_use1_private_b" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.4.0/24"
    map_public_ip_on_launch  = false
    availability_zone        = "us-east-1b"

    tags = {
        Name = "prod-use1-private-b"
    }
}

resource "aws_subnet" "prod_use1_isolated_b" {
    vpc_id                   = aws_vpc.prod_use1_vpc.id
    cidr_block               = "10.0.5.0/24"
    map_public_ip_on_launch  = false
    availability_zone        = "us-east-1b"

    tags = {
        Name = "prod-use1-isolated-b"
    }
}

#===========================================
# 10.1.0.0/16 - US-EAST-1B
#===========================================

resource "aws_subnet" "sec_use1_public_a" {
    vpc_id                   = aws_vpc.sec_use1_vpc.id
    cidr_block               = "10.1.0.0/24"
    map_public_ip_on_launch  = true
    availability_zone        = "us-east-1a"

    tags = {
        Name = "sec-use1-public-a"
    }
}

resource "aws_subnet" "sec_use1_public_b" {
    vpc_id                   = aws_vpc.sec_use1_vpc.id
    cidr_block               = "10.1.1.0/24"
    map_public_ip_on_launch  = true
    availability_zone        = "us-east-1b"

    tags = {
        Name = "sec-use1-public-b"
    }
}
```

<img width="1353" height="359" alt="subnets" src="https://github.com/user-attachments/assets/87d466cf-e431-4080-a819-b32a6e0bde6d" />



The addition of isolated subnets enforces stricter boundaires between public-facing and internal segments. Previously the architecture only included public and private subnets.

### 3. Explicit Routing, NACLs, & Security Groups
Network segmentation from the previous secure networking project was extended by providing the new subnets with their own route tables, network ACLs, and security groups. An additional NAT gateway was deployed for the second AZ following to align with high availability best practices.

Routing:
```
#===========================================
# 10.0.0.0/16 - US-EAST-1A
#===========================================
resource "aws_route_table" "prod_use1_rt_public_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.prod_use1_igw.id
    }

    route {
        cidr_block                = var.sec_vpc_cidr_block
        vpc_peering_connection_id = aws_vpc_peering_connection.prod_to_sec.id
    }

    tags = {
        Name = "prod-use1-rt-public-a"
    }
}

resource "aws_route_table_association" "prod_use1_rt_public_a_assoc" {
    subnet_id      = aws_subnet.prod_use1_public_a.id
    route_table_id = aws_route_table.prod_use1_rt_public_a.id
}

resource "aws_route_table" "prod_use1_rt_private_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    route {
        cidr_block     = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.prod_use1_nat_a.id 
    }

    tags = {
        Name = "prod-use1-rt-private-a"
    }
}

resource "aws_route_table_association" "prod_use1_rt_private_a_assoc" {
    subnet_id      = aws_subnet.prod_use1_private_a.id
    route_table_id = aws_route_table.prod_use1_rt_private_a.id
}

resource "aws_route_table" "prod_use1_rt_isolated_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id

   ## Local Routes only

    tags = {
        Name = "prod-use1-rt-isolated-a"
    }
}

resource "aws_route_table_association" "prod_use1_rt_isolated_a_assoc" {
    subnet_id      = aws_subnet.prod_use1_isolated_a.id
    route_table_id = aws_route_table.prod_use1_rt_isolated_a.id
}

#===========================================
# 10.0.0.0/16 - US-EAST-1B
#===========================================
resource "aws_route_table" "prod_use1_rt_public_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.prod_use1_igw.id
    }

    route {
        cidr_block                = var.sec_vpc_cidr_block
        vpc_peering_connection_id = aws_vpc_peering_connection.prod_to_sec.id
    }

    tags = {
        Name = "prod-use1-rt-public-b"
    }
}

resource "aws_route_table_association" "prod_use1_rt_public_b_assoc" {
    subnet_id      = aws_subnet.prod_use1_public_b.id
    route_table_id = aws_route_table.prod_use1_rt_public_b.id
}

resource "aws_route_table" "prod_use1_rt_private_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    route {
        cidr_block     = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.prod_use1_nat_b.id 
    }

    tags = {
        Name = "prod-use1-rt-private-b"
    }
}

resource "aws_route_table_association" "prod_use1_rt_private_b_assoc" {
    subnet_id      = aws_subnet.prod_use1_private_b.id
    route_table_id = aws_route_table.prod_use1_rt_private_b.id
}

resource "aws_route_table" "prod_use1_rt_isolated_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id

   ## Local Routes only

    tags = {
        Name = "prod-use1-rt-isolated-b"
    }
}

resource "aws_route_table_association" "prod_use1_rt_isolated_b_assoc" {
    subnet_id      = aws_subnet.prod_use1_isolated_b.id
    route_table_id = aws_route_table.prod_use1_rt_isolated_b.id
}

#===========================================
# 10.1.0.0/16 - US-EAST-1A
#===========================================
resource "aws_route_table" "sec_use1_rt_public_a" {
    vpc_id = aws_vpc.sec_use1_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.sec_use1_igw.id
    }

    route {
        cidr_block                = var.prod_vpc_cidr_block
        vpc_peering_connection_id = aws_vpc_peering_connection.prod_to_sec.id
    }

    tags = {
        Name = "sec-use1-rt-public-a"
    }
}

resource "aws_route_table_association" "sec_use1_rt_public_a_assoc" {
    subnet_id      = aws_subnet.sec_use1_public_a.id
    route_table_id = aws_route_table.sec_use1_rt_public_a.id
}

#===========================================
# 10.1.0.0/16 - US-EAST-1B
#===========================================
resource "aws_route_table" "sec_use1_rt_public_b" {
    vpc_id = aws_vpc.sec_use1_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.sec_use1_igw.id
    }

    route {
        cidr_block                = var.prod_vpc_cidr_block
        vpc_peering_connection_id = aws_vpc_peering_connection.prod_to_sec.id
    }

    tags = {
        Name = "sec-use1-rt-public-b"
    }
}

resource "aws_route_table_association" "sec_use1_rt_public_b_assoc" {
    subnet_id      = aws_subnet.sec_use1_public_b.id
    route_table_id = aws_route_table.sec_use1_rt_public_b.id
}
```
Network ACLs:
```
#===========================================
# 10.0.0.0/16 - US-EAST-1A
#===========================================
resource "aws_network_acl" "prod_use1_nacl_public_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow peered traffic from sec-use1-vpc
    ingress {
        rule_no    = 110
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.sec_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 120
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow HTTPS
    ingress {
        rule_no    = 130
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 443
        to_port    = 443
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Allow all outbound
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-public-a"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_public_a_assoc" {
    subnet_id       = aws_subnet.prod_use1_public_a.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_public_a.id
}

resource "aws_network_acl" "prod_use1_nacl_private_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id
   
    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 110
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow all outbound for Internet access from NAT
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-private-a"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_private_a_assoc" {
    subnet_id       = aws_subnet.prod_use1_private_a.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_private_a.id
}

resource "aws_network_acl" "prod_use1_nacl_isolated_a" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Outbound - allow VPC
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Outbound - deny all else
    egress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-isolated-a"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_isolated_a_assoc" {
    subnet_id       = aws_subnet.prod_use1_isolated_a.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_isolated_a.id
}

#===========================================
# 10.0.0.0/16 - US-EAST-1B
#===========================================
resource "aws_network_acl" "prod_use1_nacl_public_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow peered traffic from sec-use1-vpc
    ingress {
        rule_no    = 110
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.sec_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 120
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow HTTPS
    ingress {
        rule_no    = 130
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 443
        to_port    = 443
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Allow all outbound
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-public-b"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_public_b_assoc" {
    subnet_id       = aws_subnet.prod_use1_public_b.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_public_b.id
}

resource "aws_network_acl" "prod_use1_nacl_private_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id
   
    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 110
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow all outbound for Internet access from NAT
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-private-b"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_private_b_assoc" {
    subnet_id       = aws_subnet.prod_use1_private_b.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_private_b.id
}

resource "aws_network_acl" "prod_use1_nacl_isolated_b" {
    vpc_id = aws_vpc.prod_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Outbound - allow VPC
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Outbound - deny all else
    egress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "prod-use1-nacl-isolated-b"
    }
}

resource "aws_network_acl_association" "prod_use1_nacl_isolated_b_assoc" {
    subnet_id       = aws_subnet.prod_use1_isolated_b.id
    network_acl_id  = aws_network_acl.prod_use1_nacl_isolated_b.id
}

#===========================================
# 10.1.0.0/16 - US-EAST-1A
#===========================================
resource "aws_network_acl" "sec_use1_nacl_public_a" {
    vpc_id = aws_vpc.sec_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.sec_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow peered traffic from prod-use1-vpc
    ingress {
        rule_no    = 110
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 120
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow HTTPS
    ingress {
        rule_no    = 130
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 443
        to_port    = 443
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Allow all outbound
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "sec-use1-nacl-public-a"
    }
}

resource "aws_network_acl_association" "sec_use1_nacl_public_a_assoc" {
    subnet_id       = aws_subnet.sec_use1_public_a.id
    network_acl_id  = aws_network_acl.sec_use1_nacl_public_a.id
}

#===========================================
# 10.1.0.0/16 - US-EAST-1B
#===========================================
resource "aws_network_acl" "sec_use1_nacl_public_b" {
    vpc_id = aws_vpc.sec_use1_vpc.id

    # Allow VPC traffic
    ingress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.sec_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow peered traffic from prod-use1-vpc
    ingress {
        rule_no    = 110
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.prod_vpc_cidr_block
        from_port  = 0
        to_port    = 0
    }

    # Allow ephemeral response traffic (1024-65535)
    ingress {
        rule_no    = 120
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 1024
        to_port    = 65535
    }

    # Allow HTTPS
    ingress {
        rule_no    = 130
        protocol   = "tcp"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 443
        to_port    = 443
    }

    # Deny All 
    ingress {
        rule_no    = 200
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    # Allow all outbound
    egress {
        rule_no    = 100
        protocol   = "-1"
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
    }

    tags = {
        Name = "sec-use1-nacl-public-b"
    }
}

resource "aws_network_acl_association" "sec_use1_nacl_public_b_assoc" {
    subnet_id       = aws_subnet.sec_use1_public_b.id
    network_acl_id  = aws_network_acl.sec_use1_nacl_public_b.id
}
```
Security Groups:
```
#===========================================
# 10.0.0.0/16 - US-EAST-1A
#===========================================
resource "aws_security_group" "prod_use1_sg_public_a" {
    name        = "prod-use1-sg-public-a"
    description = "Public Subnet traffic" 
    vpc_id      = aws_vpc.prod_use1_vpc.id

    ingress {
        description  = "HTTPS"
        from_port    = 443
        to_port      = 443
        protocol     = "tcp"
        cidr_blocks  = ["0.0.0.0/0"]
    }

    ingress {
        description  = "Allow traffic from peered VPC"
        from_port    = 0
        to_port      = 0
        protocol     = "-1"
        cidr_blocks  = [aws_vpc.sec_use1_vpc.cidr_block]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "prod-use1-sg-public-a"
    }
}

resource "aws_security_group" "prod_use1_sg_private_a" {
    name        = "prod-use1-sg-private-a"
    description = "Private Subnet traffic"
    vpc_id      = aws_vpc.prod_use1_vpc.id

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "prod-use1-sg-private-a"
    }
}

resource "aws_security_group" "prod_use1_sg_isolated_a" {
    name        = "prod-use1-sg-isolated-a"
    description = "Isolated traffic" 
    vpc_id      = aws_vpc.prod_use1_vpc.id

    ingress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [aws_vpc.prod_use1_vpc.cidr_block]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [aws_vpc.prod_use1_vpc.cidr_block]
    }

    tags = {
        Name = "prod-use1-sg-isolated-a"
    }
}

#===========================================
# 10.0.0.0/16 - US-EAST-1B
#===========================================
resource "aws_security_group" "prod_use1_sg_public_b" {
    name        = "prod-use1-sg-public-b"
    description = "Public Subnet traffic" 
    vpc_id      = aws_vpc.prod_use1_vpc.id

    ingress {
        description  = "HTTPS"
        from_port    = 443
        to_port      = 443
        protocol     = "tcp"
        cidr_blocks  = ["0.0.0.0/0"]
    }

    ingress {
        description  = "Allow traffic from peered VPC"
        from_port    = 0
        to_port      = 0
        protocol     = "-1"
        cidr_blocks  = [aws_vpc.sec_use1_vpc.cidr_block]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "prod-use1-sg-public-b"
    }
}

resource "aws_security_group" "prod_use1_sg_private_b" {
    name        = "prod-use1-sg-private-b"
    description = "Private Subnet traffic"
    vpc_id      = aws_vpc.prod_use1_vpc.id

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "prod-use1-sg-private-b"
    }
}

resource "aws_security_group" "prod_use1_sg_isolated_b" {
    name        = "prod-use1-sg-isolated-b"
    description = "Isolated traffic" 
    vpc_id      = aws_vpc.prod_use1_vpc.id

    ingress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [aws_vpc.prod_use1_vpc.cidr_block]
    }
    
    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [aws_vpc.prod_use1_vpc.cidr_block]
    }

    tags = {
        Name = "prod-use1-sg-isolated-b"
    }
}

#===========================================
# 10.1.0.0/16 - US-EAST-1A
#===========================================
resource "aws_security_group" "sec_use1_sg_public_a" {
    name        = "sec-use1-sg-public-a"
    description = "Allow TLS/SSH inbound traffic and outbound traffic from the public subnet." 
    vpc_id      = aws_vpc.sec_use1_vpc.id

    ingress {
        description  = "HTTPS"
        from_port    = 443
        to_port      = 443
        protocol     = "tcp"
        cidr_blocks  = ["0.0.0.0/0"]
    }
    
    ingress {
        description  = "Allow traffic from peered VPC"
        from_port    = 0
        to_port      = 0
        protocol     = "-1"
        cidr_blocks  = [aws_vpc.prod_use1_vpc.cidr_block]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "sec-use1-sg-public-a"
    }
}

#===========================================
# 10.1.0.0/16 - US-EAST-1B
#===========================================

resource "aws_security_group" "sec_use1_sg_public_b" {
    name        = "sec-use1-sg-public-b"
    description = "Allow TLS/SSH inbound traffic and outbound traffic from the public subnet." 
    vpc_id      = aws_vpc.sec_use1_vpc.id

    ingress {
        description  = "HTTPS"
        from_port    = 443
        to_port      = 443
        protocol     = "tcp"
        cidr_blocks  = ["0.0.0.0/0"]
    }
    
    ingress {
        description  = "Allow traffic from peered VPC"
        from_port    = 0
        to_port      = 0
        protocol     = "-1"
        cidr_blocks  = [aws_vpc.prod_use1_vpc.cidr_block]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "sec-use1-sg-public-b"
    }
}
```
NAT:
```
#===========================================
# 10.0.0.0/16 - US-EAST-1A
#===========================================
resource "aws_eip" "prod_use1_nat_a_eip" {
    domain = "vpc"

    tags = {
        Name = "prod-use1-nat-a-eip"
    }
}

resource "aws_nat_gateway" "prod_use1_nat_a" {
    allocation_id = aws_eip.prod_use1_nat_a_eip.id
    subnet_id     = aws_subnet.prod_use1_public_a.id
    depends_on    = [aws_internet_gateway.prod_use1_igw]

    tags = {
        Name = "prod-use1-nat-a"
    }
}

#===========================================
# 10.0.0.0/16 - US-EAST-1B
#===========================================
resource "aws_eip" "prod_use1_nat_b_eip" {
    domain = "vpc"

    tags = {
        Name = "prod-use1-nat-b-eip"
    }
}

resource "aws_nat_gateway" "prod_use1_nat_b" {
    allocation_id = aws_eip.prod_use1_nat_b_eip.id
    subnet_id     = aws_subnet.prod_use1_public_b.id
    depends_on    = [aws_internet_gateway.prod_use1_igw]

    tags = {
        Name = "prod-use1-nat-b"
    }
}
```


<img width="1648" height="348" alt="nacls" src="https://github.com/user-attachments/assets/b0d26e20-5de4-4b3c-aa5a-d272b8e2f067" />


<img width="1663" height="355" alt="sg" src="https://github.com/user-attachments/assets/5caddb2c-61e1-425e-8d12-3b4f6689ca9b" />



### 4. Centralized Network Visibility & Logging
VPC Flow Logs were previously configured and have been expanded to include the new subnets, ensuring consistent network visibility across the environment.



<img width="1727" height="787" alt="flowlogs" src="https://github.com/user-attachments/assets/44405173-b2b0-492a-b3f7-06dbd5f24513" />

```
# VPC CloudWatch Log Group
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
    name              = "/aws/vpc/flow-logs"
    retention_in_days = 30  
}

   # IAM Role for VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs_role" {
    name = "VPCFlowLogsRole"

    assume_role_policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [
            {
                Action    = "sts:AssumeRole"
                Effect    = "Allow"
                Principal = {
                    Service = "vpc-flow-logs.amazonaws.com"
                }
            }
        ]
    })
}

   # IAM Policy for VPC Flow Logs
resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
    name = "vpc-flow-logs-policy"
    role = aws_iam_role.vpc_flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
        Effect = "Allow"
        Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
      ]
         Resource = "*"
    }]
  })
}

   # Prod VPC Flow Logs
resource "aws_flow_log" "main_vpc_flow" {
    vpc_id               = aws_vpc.prod_use1_vpc.id
    log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
    log_destination_type = "cloud-watch-logs"
    traffic_type         = "ALL"
    iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
}

   # Security VPC Flow Logs
resource "aws_flow_log" "vpc2_flow" {
    vpc_id               = aws_vpc.sec_use1_vpc.id
    log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
    log_destination_type = "cloud-watch-logs"
    traffic_type         = "ALL"
    iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
}
```
### 5. Scalable Terraform Naming & Structure
As part of this iteration, Terraform resources and variables were refactored to follow a consistent, scalable naming convention. This improves maintainability, enables predictable resource identification, and simplifies scalability. Overall, this allows the infrastructure to scale without requiring significant refactoring as new components are introduced.


<img width="1652" height="363" alt="EC2" src="https://github.com/user-attachments/assets/6fbfdf05-f9e1-429d-be95-074802c47d30" />

### 6. Security-Ready Architecture
The second VPC was originally used for test connectivity between VPCs using VPC Peering. It's now ready to operate as a dedicated environment for future cloud security projects, including threat detection, security monitoring, and incident response tooling within AWS.



<img width="1627" height="283" alt="vpcpeering" src="https://github.com/user-attachments/assets/a2d41051-e887-415d-ae80-438589fea5bc" />

## Design Decisions

### High Availability as a Baseline
The network was designed with Availability Zone failure in mind. All critical components were deployed per AZ to eliminate single points of failure and aligns with AWS high availability best practices.

### Defense-in-Depth & Least-Privilege through Segmentation
Different subnet tiers were separated to enforce boundaries between public-facing resources, internal workloads, and sensitive systems. Additionally, network security measures like NACLs and security groups were applied to prevent broad access and harden the network by preventing access and traffic that isn't necessary.

### Avoiding Cross-AZ Dependency
NAT gateways and routing were designed to remain AZ-local to prevent cross-AZ traffic dependencies, reduce blast radius, and avoid unnecessary latency.

### Observability  
Network visibility is a core requirement, flow logs across all subnet tiers ensures the enivronment is ready for monitoring, detection and incident response use cases.

### Terraform Built for Scalability & Consistency
Terraform naming and structure were designed to scale across additional environments, regions, and accounts without requiring refactoring, supporting long-term maintainability.
