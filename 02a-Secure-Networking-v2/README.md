# AWS Secure Networking v2

This iteration of the secure networking project represents an evolution from my previous Terraform networking work. The original established foundational, secure network architecture with multiple VPCs, routing, nacls, etc. This version focuses on high availability, fault tolerance, and long-term scalability aligned with production-grade AWS environments. 

This is a major refinement of my previous my network architecture and refactoring of my Terraform code that will be used in future cloud security projects.

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

## Network Diagram
  ### Before

  ### After
   
## Key Enhancements
### 1. Multi-AZ Deployment
Subnets are now provisioned across multiple availability zones to ensure high availability and tolerance for zone failures. This significantly improves the reliability of my architecture and shifts away with the original scope of a single AZ.

### 2. Inclusion of the isolated subnet
The architecure now includes:
  - Public Subnets (Internet Access)
  - Private Subnets (Egress internet access using NAT)
  - Isolated Subnets (NO INTERNET ACCESS) - For future sensitive data and/or tooling

The addition of isolated subnets enforces stricter boundaires between public-facing and internal segments. I previously only had public and private subnets.

### 3. Explicit Routing, NACLs, & Security Groups
I continued the network segmentation of my previous secure networking project and provided the new subnets with their own route tables, network ACLs, and security groups. I also provided another NAT gateway for the additional AZ following the high availability process.

### 4. Centralized Network Visibilty & Logging
VPC Flow Logs were previously set up and now include the new subnets.

### 5. Scalable Terraform Naming & Structure
As part of this iteration, Terraform resources and variables were refactored to follow a consistent, scalable naming convention. This improves maintainability, predictable resource identification, and easy scalability. Overall, this enables the infrastructure to scale without requiring significant refactoring as new components are introduced.

### 6. Security-Ready Architecture
The second VPC was primarily used for testing connectivity between VPCs using Peering. This VPC is now ready for future cloud security projects: threat detection, security monitoring, and incident response that use their own tooling and services within AWS.
