# AWS Secure Networking v2

This iteration of the secure networking project represents an evolution of my previous Terraform networking work. The original established foundational, secure network architecture with multiple VPCs, routing, NACLs, and segmentation. This version focuses on high availability, fault tolerance, and long-term scalability aligned with production-grade AWS environments. 

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

  ### After
   
## Key Enhancements
### 1. Multi-AZ Deployment
Subnets are now provisioned across multiple Availability Zones to ensure high availability and tolerance for AZ-level outages. This significantly improves the reliability of the architecture and shifts away from the original single-AZ design.

### 2. Inclusion of the Isolated Subnet
The architecure now includes:
  - Public Subnets (Internet Access)
  - Private Subnets (Egress internet access using NAT)
  - Isolated Subnets (NO INTERNET ACCESS) - For future sensitive data and/or tooling

The addition of isolated subnets enforces stricter boundaires between public-facing and internal segments. Previously the architecture only included public and private subnets.

### 3. Explicit Routing, NACLs, & Security Groups
Network segmentation from the previous secure networking project was extended by providing the new subnets with their own route tables, network ACLs, and security groups. An additional NAT gateway was deployed for the second AZ following to align with high availability best practices.

### 4. Centralized Network Visibility & Logging
VPC Flow Logs were previously configured and have been expanded to include the new subnets, ensuring consistent network visibility across the environment.

### 5. Scalable Terraform Naming & Structure
As part of this iteration, Terraform resources and variables were refactored to follow a consistent, scalable naming convention. This improves maintainability, enables predictable resource identification, and simplifies scalability. Overall, this allows the infrastructure to scale without requiring significant refactoring as new components are introduced.

### 6. Security-Ready Architecture
The second VPC was originally used for test connectivity between VPCs using VPC Peering. It's now ready to operate as a dedicated environment for future cloud security projects, including threat detection, security monitoring, and incident response tooling within AWS.

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
