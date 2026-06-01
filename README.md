# AWS Automated Security Posture Management (CSPM) Engine

An automated, event-driven security tool built in Python using **Boto3** to scan AWS infrastructure for critical vulnerabilities and programmatically execute incident response remediation.

## 🚀 Project Overview
In a cloud environment, misconfigured storage buckets and stale identity credentials represent significant data breach vectors. This project simulates a real-world **Detective and Responsive Control** pipeline. 

It programmatically:
1. Deploys an infrastructure test environment in AWS.
2. Scans the environment to identify compliance failures (Public S3 Buckets & Stale IAM Access Keys).
3. Executes automated real-time mitigation to block public exposure instantly.

---

## 🛠️ Architecture & Core Components

- **Infrastructure Layer:** Programmatically spins up a securely encrypted compliance bucket alongside an intentionally insecure testing bucket (`ap-south-1` region compliance).
- **Detective Controls:** Queries the AWS S3 and IAM endpoints to evaluate configurations against security benchmarks.
- **Automated Remediation:** Instantly deploys an AWS `PublicAccessBlockConfiguration` to neutralize any detected public exposure.

---

## 📋 Prerequisites & Setup

### 1. Installation
Install the required AWS SDK for Python:
Bash:
pip install boto3

## Configure your machine with AWS IAM User credentials (ensuring least-privilege permissions for S3 and IAM):

Bash: 
aws configure

Note: Provide your Access Key ID, Secret Access Key, and target region (e.g., ap-south-1).

## 💻 Usage & Execution
To run the compliance scanner and remediation engine:

Bash
python cloud_security_engine.py

## 📊 Proof of Execution & Verification
1. Terminal Scan & Debug Logs

The script evaluates the infrastructure, surfaces threats in a clean JSON format, and triggers immediate repair:
![Terminal Scan & Debug Logs](/screenshots/secure_engine_debug_op.png)

3. AWS Console Verification

Below is the verification screenshot confirming that the engine successfully modified the insecure bucket's configuration to "Bucket and objects not public" via API automation:
![AWS Console Verification](/screenshots/automate_remediation_console_op.png)

## 🛡️ Key Lessons Learned
S3 Regional Constraints: Mastered handling IllegalLocationConstraintException by explicitly pairing CreateBucketConfiguration with regional client endpoints outside of us-east-1.

Error Handling (Boto3): Leveraged botocore.exceptions.ClientError to catch missing bucket configurations (NoSuchPublicAccessBlockConfiguration) and accurately escalate threat severity from HIGH to CRITICAL.



