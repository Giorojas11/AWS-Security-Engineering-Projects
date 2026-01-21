# Identity Governance & Preventive Security Control

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



<img width="936" height="630" alt="cliaccounts" src="https://github.com/user-attachments/assets/d280b83f-c69f-451c-8918-fa43fb3732ed" />

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



<img width="833" height="629" alt="OUs-accts" src="https://github.com/user-attachments/assets/007e37ab-561f-48ff-8836-b64c1939aeea" />

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




<img width="1610" height="318" alt="grps" src="https://github.com/user-attachments/assets/9d7d911a-8cbf-4af6-bc83-a83f56236d5b" />

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




<img width="665" height="368" alt="identity-users" src="https://github.com/user-attachments/assets/72226ad2-b246-49f7-a03e-ed9532303e73" />

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




### Policy --> Permission Set
<img width="1623" height="627" alt="adminperms" src="https://github.com/user-attachments/assets/bd6f4b1d-951e-4af7-906a-36faad81cd42" />
<img width="1616" height="619" alt="devperms" src="https://github.com/user-attachments/assets/a671a342-6010-405d-a6ba-3c96901bcca2" />
<img width="1629" height="661" alt="secperms" src="https://github.com/user-attachments/assets/25b64735-0e3e-40b3-8eb3-1e32587538bd" />




### Permission Set --> Account
<img width="1601" height="682" alt="adminpermaccount" src="https://github.com/user-attachments/assets/ba1a76e5-6876-49b6-840b-df0dbb60e0c8" />
<img width="1589" height="683" alt="devpermaccount" src="https://github.com/user-attachments/assets/4d80eaf3-1781-41e0-91c8-cb29adac7dde" />
<img width="1647" height="690" alt="secpermsaccounts" src="https://github.com/user-attachments/assets/0f881e36-1e2e-42eb-89b6-842415dd4120" />




### Users --> Groups
<img width="1591" height="518" alt="usergroupadmin" src="https://github.com/user-attachments/assets/3eb71ebc-1fa5-46dc-8a52-936d8b4378e2" />
<img width="1593" height="535" alt="usergroupdev" src="https://github.com/user-attachments/assets/b0e93421-b85b-4dc5-b3dd-81bb019e49e5" />
<img width="1608" height="532" alt="usergroupsec" src="https://github.com/user-attachments/assets/2cebc559-d133-45be-8ad1-47e0bc6b02e2" />




### Groups --> Accounts via Permission Set
<img width="753" height="643" alt="admin-group-to-account" src="https://github.com/user-attachments/assets/d12b3705-3116-4897-a6cb-23938f2436f7" />
<img width="750" height="646" alt="dev-group-to-account" src="https://github.com/user-attachments/assets/5c03573d-7a18-4ea8-b76a-b69f7c32621c" />
<img width="763" height="634" alt="sec-group-to-account" src="https://github.com/user-attachments/assets/125a699b-bfeb-499a-8e09-78c63b46c7a9" />




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




<img width="1334" height="716" alt="denysecdisablescp" src="https://github.com/user-attachments/assets/9aff1804-bb2d-426b-9526-7eeb541278f1" />

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


<img width="924" height="419" alt="AA-delegated" src="https://github.com/user-attachments/assets/f523ba39-3511-43a1-a7c4-76a0571031be" />

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

  


<img width="626" height="325" alt="Root" src="https://github.com/user-attachments/assets/edf1bf8c-05c1-45a7-b3ef-176af708d0d2" />




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





<img width="1796" height="723" alt="policy-sim-admin-poc" src="https://github.com/user-attachments/assets/bf2d9282-7df4-413d-a67f-00438b6dde1b" />
<img width="1809" height="758" alt="policysim-PoC-dev1" src="https://github.com/user-attachments/assets/713acf0e-2e7f-438c-99a5-ce3959ad29c6" />
<img width="1781" height="824" alt="secanalyst-policysim-poc" src="https://github.com/user-attachments/assets/35b4f296-7c31-4702-a792-979a4100e1c4" />





- Permission sets validated through real user logins.





<img width="1566" height="755" alt="admin-iam-access" src="https://github.com/user-attachments/assets/dc8930a7-a4be-47d4-b90c-d2bb8d897376" />
<img width="1600" height="598" alt="dev-iam-denied" src="https://github.com/user-attachments/assets/03d517c9-de56-4496-be45-eaf2d582470b" />




- Access Analyzer findings were generated, reviewed, and resolved.





<img width="1903" height="692" alt="access-analyzer-finding" src="https://github.com/user-attachments/assets/1fe6a563-0bb8-42df-9ef4-f4c6b2764559" />





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
