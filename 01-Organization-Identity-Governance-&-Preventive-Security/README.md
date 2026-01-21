# Organizations, Identity Governance, & Preventive Security

  This project implements enterprise-grade identity governance and preventive security controls using AWS Organizations, IAM Identity Center, Service Control Policies (SCPs), and IAM Access Analyzer.

  The goal is to demonstrate how large-scale AWS environments enforce security centrally rather than relying on account-based IAM permissions alone. This design prioritizes blast radius reduction, least privilege, auditability, and compliance alignment while remaining automation-first using Terraform.

This project is the identity and governance foundation for future security controls.

------------------------------------

## Table of Contents
  1. [Architecture Overview](#1-architecture-overview)
  2. [Threat Model](#2-threat-model)
  3. [AWS Organizations](#3-aws-organizations)
  4. [Identity & Access Management Strategy](#4-identity--access-management-strategy)
  5. [Service Control Policies - Preventative Guardrails](#5-service-control-policies---preventative-guardrails)
  6. [IAM Access Analyzer - Continuous Risk Detection](#6-iam-access-analyzer---continuous-risk-detection)
  7. [Root Account](#7-root-account)
  8. [Compliance & Framework Alignment](#8-compliance--framework-alignment)
  9. [Validation & Evidence](#9-validation--evidence)
  10. [Key Takeaways](#10-key-takeaways)

---------------------------------------

## 1. Architecture Overview
#### Multi-account AWS Organization with centralized identity and security governance.

### Design Principles
- Centralized control
- Explicit deny over implicit allow
- Identity as the primary security boundary
- Preventative over detective controls where applicable

### Accounts
- Management Account - root-level billing and organizational control
- Security Account - Delegated security administrator of cloud security & security tooling
- Production Account - Workloads & services
- Log Archives Account - *Future centralized logging



<img width="936" height="630" alt="cliaccounts" src="https://github.com/user-attachments/assets/04f63e3f-bb7e-4e5e-962d-6066f77afa01" />

```
resource "aws_organizations_account" "security" {
    name      = "security-account"
    email     = "grojasaws+security@gmail.com"

    parent_id = aws_organizations_organizational_unit.security.id
}

resource "aws_organizations_account" "log_archive" {
    name      = "log-archive-account"
    email     = "grojasaws+logs@gmail.com"

    parent_id = aws_organizations_organizational_unit.log_archive.id
}

resource "aws_organizations_account" "prod" {
    name      = "production-account"
    email     = "grojasaws+prod@gmail.com"

    parent_id = aws_organizations_organizational_unit.production.id
}
```

### Organizational Units (OUs)
- Security OU
- Production OU
- Log Archives OU



<img width="833" height="629" alt="OUs-accts" src="https://github.com/user-attachments/assets/00d78c75-40d0-46fa-a4d0-4b288da1f014" />

```
resource "aws_organizations_organizational_unit" "security" {
    name      = "Security"
    parent_id =  aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "production" {
    name      = "Production"
    parent_id =  aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "log_archive" {
    name      = "Log-Archives"
    parent_id =  aws_organizations_organization.org.roots[0].id
}
```

### Groups
- Security Group
- Administrators
- Developer Group


<img width="1610" height="318" alt="grps" src="https://github.com/user-attachments/assets/d5ab4a74-f7c5-4a1b-bf51-b1e75b313721" />

```
resource "aws_identitystore_group" "security" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0] 
    display_name      = "Security Group"
}

resource "aws_identitystore_group" "admins" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0] 
    display_name      = "Administrators"
}

resource "aws_identitystore_group" "dev" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0] 
    display_name      = "Developer Group"
}
```

### Users
- Sec-Analyst-1
- Admin-1
- Dev-1
- Root - Management Account
- GROJAS-IAM-ADMIN - Break-Glass Administration



<img width="665" height="368" alt="identity-users" src="https://github.com/user-attachments/assets/65b25856-8a05-458c-853f-4268a5f7007d" />

```
resource "aws_identitystore_user" "security_analyst" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    user_name         = "sec-analyst-1"
    display_name      = "sec-analyst-1"

    name {
        given_name  = "Security"
        family_name = "Analyst"
    }
}

resource "aws_identitystore_user" "admin1" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    user_name         = "admin-1"
    display_name      = "admin-1"

    name {
        given_name  = "Admin"
        family_name = "1"
    }
}

resource "aws_identitystore_user" "dev1" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    user_name         = "dev-1"
    display_name      = "dev-1"

    name {
        given_name  = "Dev"
        family_name = "1"
    }
}
```

### Permission Sets
- SecurityReadOnly
- AdminPermissions
- Developer

```
resource "aws_ssoadmin_permission_set" "security_readonly" {
    name             = "SecurityReadOnly"
    instance_arn     = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    session_duration = "PT8H"
}

resource "aws_ssoadmin_permission_set" "admin" {
    name             = "AdminPermissions"
    instance_arn     = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    session_duration = "PT8H"
}

resource "aws_ssoadmin_permission_set" "developer" {
    name             = "Developer"
    instance_arn     = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    session_duration = "PT8H"
}
```

### Policy Attachment & Account Assignment
```
resource "aws_ssoadmin_managed_policy_attachment" "security_audit" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.security_readonly.arn
    managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_ssoadmin_managed_policy_attachment" "security_read_only" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.security_readonly.arn
    managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_ssoadmin_account_assignment" "security_assignment" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.security_readonly.arn

    principal_id       = aws_identitystore_group.security.group_id
    principal_type     = "GROUP"

    target_id          = aws_organizations_account.security.id
    target_type        = "AWS_ACCOUNT"

    depends_on = [
        aws_identitystore_group.security,
        aws_ssoadmin_permission_set.security_readonly,
        aws_ssoadmin_managed_policy_attachment.security_audit,
        aws_ssoadmin_managed_policy_attachment.security_read_only
    ]
}

resource "aws_ssoadmin_account_assignment" "logarchive_assignment" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.security_readonly.arn

    principal_id       = aws_identitystore_group.security.group_id
    principal_type     = "GROUP"

    target_id          = aws_organizations_account.log_archive.id
    target_type        = "AWS_ACCOUNT"

    depends_on = [
        aws_identitystore_group.security,
        aws_ssoadmin_permission_set.security_readonly,
        aws_ssoadmin_managed_policy_attachment.security_audit,
        aws_ssoadmin_managed_policy_attachment.security_read_only
    ]
}

resource "aws_identitystore_group_membership" "sec_user_join" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    group_id          = aws_identitystore_group.security.group_id
    member_id         = aws_identitystore_user.security_analyst.user_id
}

resource "aws_ssoadmin_managed_policy_attachment" "admin_policy" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn =  aws_ssoadmin_permission_set.admin.arn
    managed_policy_arn =  "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_ssoadmin_account_assignment" "admin_assignment" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.admin.arn

    principal_id       = aws_identitystore_group.admins.group_id
    principal_type     = "GROUP"

    target_id          = aws_organizations_account.prod.id
    target_type        = "AWS_ACCOUNT"

    depends_on = [
        aws_identitystore_group.admins,
        aws_ssoadmin_permission_set.admin,
        aws_ssoadmin_managed_policy_attachment.admin_policy
    ]
}

resource "aws_identitystore_group_membership" "admin_user_join" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    group_id          = aws_identitystore_group.admins.group_id
    member_id         = aws_identitystore_user.admin1.user_id
}

resource "aws_ssoadmin_managed_policy_attachment" "developer_poweruser" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.developer.arn
    managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_ssoadmin_account_assignment" "dev_assignment" {
    instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
    permission_set_arn = aws_ssoadmin_permission_set.developer.arn

    principal_id       = aws_identitystore_group.dev.group_id
    principal_type     = "GROUP"

    target_id          = aws_organizations_account.prod.id
    target_type        = "AWS_ACCOUNT"

    depends_on = [
        aws_identitystore_group.dev,
        aws_ssoadmin_permission_set.developer,
        aws_ssoadmin_managed_policy_attachment.developer_poweruser
    ]
}

resource "aws_identitystore_group_membership" "dev_user_join" {
    identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
    group_id          = aws_identitystore_group.dev.group_id
    member_id         = aws_identitystore_user.dev1.user_id
}
```

## 2. Threat Model
Controls are designed to fail safely by preventing high-impact actions and limiting blast radius, even when credentials are compromised.

### Threats Addressed
- Preventing accidental or malicious disabling of security services like GuardDuty, Security Hub, CloudTrail, etc.
- Overly-permissive IAM roles by enforcing role-based access, separation of duties, and least privilege.
- Root Account Abuse
- Multi-account IAM sprawl
- Cross-account misconfigurations
- Lack of identity-based risk detection through Access Analyzer

## 3. AWS Organizations
The organization is created with ALL features enabled, allowing:
- Service Control Policies
- Delegated Administrators
- Organization-wide security services
- Centralized IAM and governance
```
resource "aws_organizations_organization" "org" {
    feature_set = "ALL"
    aws_service_access_principals = [
        "access-analyzer.amazonaws.com",
        "sso.amazonaws.com",
        "guardduty.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "securityhub.amazonaws.com"
        ]

    enabled_policy_types = [
        "SERVICE_CONTROL_POLICY"
    ]
}

data "aws_ssoadmin_instances" "sso" {}
```
### Why ALL features?
Without ALL features, SCPs and delegated security services won't work. This would limit governance which doesn't scale.

## 4. Identity & Access Management Strategy
  IAM is managed through IAM Identity Center which allows for centralization of accounts, users, and permissions. This avoids per-account IAM users, password and key sprawl, and common auditing challenges. It enables central access control, consistency, and auditability.

### Permission Sets Implemented
- SecurityReadOnly - Audit and investigation access
- AdminPermissions - Full administrative access to the Production account
- Developer - PowerUser access without IAM/Organizational control



<img width="1623" height="627" alt="adminperms" src="https://github.com/user-attachments/assets/ca1744c7-dbc2-43ff-94f6-f500c074e651" />
<img width="1616" height="619" alt="devperms" src="https://github.com/user-attachments/assets/f9d107e9-ab72-4c2b-b5be-1e2cc93a0942" />
<img width="1629" height="661" alt="secperms" src="https://github.com/user-attachments/assets/94b7640a-87d2-4162-9a73-36aa55353241" />



### Users to Groups
<img width="1591" height="518" alt="usergroupadmin" src="https://github.com/user-attachments/assets/1af53fdb-d851-44de-8762-cf7e0867f914" />
<img width="1593" height="535" alt="usergroupdev" src="https://github.com/user-attachments/assets/735e66ad-353e-44e0-85cf-21a98e0ce082" />
<img width="1608" height="532" alt="usergroupsec" src="https://github.com/user-attachments/assets/a0868680-cf48-4159-bb8e-bed53496a35b" />




### Groups to Accounts
<img width="1601" height="682" alt="adminpermaccount" src="https://github.com/user-attachments/assets/ebff9b23-dcb7-4bf6-a314-07f2d010106d" />
<img width="1589" height="683" alt="devpermaccount" src="https://github.com/user-attachments/assets/8d973327-a100-4a59-a8ab-1dd545982174" />
<img width="1647" height="690" alt="secpermsaccounts" src="https://github.com/user-attachments/assets/6aa8507e-3a8c-475c-ab92-a1480334458e" />



## 5. Service Control Policies - Preventative Guardrails
SCPs are organization-level policies that are used to enforce non-negotiable security rules across all accounts.

### Examples of Blocked Actions
- Disabling CloudTrail
- Deleting or stopping GuardDuty
- Disabling Security Hub
- Modifying logging controls

### Benefits
- SCPs provide a boundary that even administrator access cannot bypass.
- Prevents misconfigurations at organizational scale.
- Enforces executive-level security decisions consistently across all accounts.


<img width="1334" height="716" alt="denysecdisablescp" src="https://github.com/user-attachments/assets/f7ab96b3-6fe3-47a3-afd1-6c3669b51304" />

```
resource "aws_organizations_policy" "deny_disable_security" {
    name        = "DenyDisableSecurityServices"
    description = "Prevents disabling of critical security services"
    type        = "SERVICE_CONTROL_POLICY"

    content = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Deny"
                Action = [
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                    "guardduty:DisableOrganizationAdminAccount",
                    "guardduty:DeleteDetector",
                    "guardduty:Disassociate*",
                    "securityhub:DeleteInviations",
                    "securityhub:DisableSecurityHub"
                ]
                Resource = "*"
            }
        ]
    })
}

resource "aws_organizations_policy_attachment" "security_attach_prod" {
    policy_id = aws_organizations_policy.deny_disable_security.id
    target_id = aws_organizations_organizational_unit.production.id
}

resource "aws_organizations_policy_attachment" "security_attach_logarchive" {
    policy_id = aws_organizations_policy.deny_disable_security.id
    target_id = aws_organizations_organizational_unit.log_archive.id
}

resource "aws_organizations_policy_attachment" "security_attach_security" {
    policy_id = aws_organizations_policy.deny_disable_security.id
    target_id = aws_organizations_organizational_unit.security.id
}
```

## 6. IAM Access Analyzer - Continuous Risk Detection
  IAM Access Analyzer is enabled organization-wide, with the Security account as the delegated administrator. This provides continuous identity risk visibility and detection without manual policy reviews across accounts.

### What It Detects
- External access to AWS resources
- Public access exposure
- Unused or permissive access
- Cross-account access paths



<img width="924" height="419" alt="AA-delegated" src="https://github.com/user-attachments/assets/4ec7b7f8-111a-48bf-a328-712db89b6746" />

```
resource "aws_organizations_delegated_administrator" "access_analyzer" {
    service_principal = "access-analyzer.amazonaws.com"
    account_id        = aws_organizations_account.security.id
}

resource "aws_accessanalyzer_analyzer" "org" {
    analyzer_name = "org-access-analyzer"
    type          = "ORGANIZATION"

    depends_on = [ 
        aws_organizations_organization.org,
        aws_organizations_delegated_administrator.access_analyzer
     ]
}
```


## 7. Root Account
  The root account gives you access to some of the most critical actions possible in AWS. Gaining access to root would allow someone to change account settings, close the account, and access billing and cost management. It is imperative that the root account stay secured and limited to very specific use cases.

  

<img width="626" height="325" alt="Root" src="https://github.com/user-attachments/assets/ee5d500a-f494-4a16-90fb-5dfae6d826ec" />



### Controls Implemented
- MFA enabled
- Strong, complex password
- No access keys created (ever)
- No daily usage
- Documented security posture

These controls align with AWS security best practices and meet common audit expectations found in regulated environments.

## 8. Compliance & Framework Alignment
This project aims to be framework-aligned, but is not locked to any specific compliance framework.

### SOC 2 
- Logical access controls
- Least privilege enforcement
- Auditability of identity actions
- Centralized access management

### ISO 27001
- A.9 Access Control
- A.12 Logging & Monitoring
- A.6 Organizational Security Responsibilities

### HIPAA
- Unique user identification
- Access restriction by role
- Activity logging readiness
- Separation of duties

### NIST/CIS
- Centralized identity
- Root account protection
- Preventative technical controls
- Continuous risk identification

## 9. Validation & Evidence
- SCP enforcement was tested via Policy Simulator.



<img width="1796" height="723" alt="policy-sim-admin-poc" src="https://github.com/user-attachments/assets/67755cc1-333a-419f-88fd-ac7db828b62e" />
<img width="1781" height="824" alt="secanalyst-policysim-poc" src="https://github.com/user-attachments/assets/7091050a-ac3a-4c6a-a2a4-9e3af41a2aac" />
<img width="1809" height="758" alt="policysim-PoC-dev1" src="https://github.com/user-attachments/assets/ffadc8bd-f6d3-4d0a-bc0d-1aba0fd7e847" />




- Permission sets validated through real user logins.



<img width="1566" height="755" alt="admin-iam-access" src="https://github.com/user-attachments/assets/21749faf-5f83-4e7e-a6d1-de81474661ac" />
<img width="1600" height="598" alt="dev-iam-denied" src="https://github.com/user-attachments/assets/db2bbc9a-b589-45ff-9d5f-10805005029f" />



- Access Analyzer findings were generated, reviewed, and resolved.



<img width="1903" height="692" alt="access-analyzer-finding" src="https://github.com/user-attachments/assets/2f84c0ef-db42-4102-9e8e-53304d49a2b4" />




- Delegated Administrator status was verified via CloudShell.
- Root account security controls were verified and documented.



## 10. Key Takeaways
- IAM alone does not scale securely; Organizations, SCPs, and Identity Center are crucial to a secure, scalable environment.
- Whether misconfigured or malicious, IAM is one of the biggest attack surfaces in environments.
- Preventative controls reduce incident response burden by stopping breaches before they occur. As a SOC analyst, this is much appreciated.
- Compliance should not just be a checklist, it can be a byproduct of good engineering and design.

------------------------------------------------------

## Conclusion
This project establishes a production-grade IAM and governance foundation in AWS. By combining guardrails, centralized IAM, and risk detection on an organizational level, this architecture condenses and showcases how security is implemented in real-world AWS environments.
