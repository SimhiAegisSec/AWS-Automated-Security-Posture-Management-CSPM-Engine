import boto3
import botocore
import json
import time
# Initialize the AWS Boto3 client
# GCP Equivalent: storage_client = storage.Client()
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
# ---------------------------------------------------------
# CHANGE THESE VARIABLES IF YOU WANT
# ---------------------------------------------------------
BUCKET_NAME = "my-unique-security-audit-bucket-warrior-2026" 
INSECURE_BUCKET_NAME = "my-intentionally-insecure-bucket-warrior-2026"
# =========================================================
# STEP 1: COMPLIANCE ENVIRONMENT SETUP (Infrastructure)
# =========================================================
def setup_compliance_environment():
    print("\n--- [STEP 1] Setting up Secure Compliance Infrastructure ---")
    
    # 1. Create a Secure Bucket (Simulating GCP's private Bucket Lock)
    try:
        print(f"Creating Secure Audit Bucket: {BUCKET_NAME}...")
        s3_client.create_bucket(Bucket=BUCKET_NAME,
                                CreateBucketConfiguration={
            'LocationConstraint': 'ap-south-1' # fix for the IllegalLocationContraintException
        })
        
        # Enforce encryption on the bucket
        s3_client.put_bucket_encryption(
            Bucket=BUCKET_NAME,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        print(f"✅ Success: {BUCKET_NAME} created and encrypted.")
    except Exception as e:
        print(f"ℹ️ Note: Secure bucket setup skipped (likely already exists): {e}")

# 2. Create an INSECURE Bucket for testing purposes
    try:
        print(f"Creating Insecure Testing Bucket: {INSECURE_BUCKET_NAME}...")
        s3_client.create_bucket(Bucket=INSECURE_BUCKET_NAME,
                                CreateBucketConfiguration={
            'LocationConstraint': 'ap-south-1' # fix for the IllegalLocationContraintException
        })
        print(f"⚠️ Warning Setup: {INSECURE_BUCKET_NAME} created with zero security configurations.")
    except Exception as e:
        print(f"ℹ️ Note: Insecure bucket setup skipped: {e}")

# =========================================================
# STEP 2: DETECTIVE CONTROLS (Security Scanning)
# =========================================================
def run_security_scan():
    print("\n--- [STEP 2] Running Detective Controls (Security Scanner) ---")
    findings = []
# Check 1: Scan for S3 Buckets missing Public Access Blocks
    print("Scanning storage layers for public exposure dangers...")
    buckets = s3_client.list_buckets()['Buckets']
    
    for b in buckets:
        name = b['Name']
        try:
            # Check if public access is blocked
            status = s3_client.get_public_access_block(Bucket=name)
            pab = status['PublicAccessBlockConfiguration']
            if not pab['BlockPublicPolicy'] or not pab['BlockPublicAcls']:
                findings.append({"resource": name, "type": "S3_Bucket", "issue": "Public Access NOT Blocked", "severity": "HIGH"})
        except botocore.exceptions.ClientError as e:
            # If get_public_access_block throws an error, it means no configuration exists (it is public!)
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                findings.append({"resource": name, "type": "S3_Bucket", "issue": "Public Access Configuration Missing entirely", "severity": "CRITICAL"})
# Check 2: Scan IAM User Root/Access Keys (Simulating GCP Service Account Key hygiene)
    print("Scanning Identity Layer (IAM) for stale credentials...")
    users = iam_client.list_users()['Users']
    for user in users:
        username = user['UserName']
        keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            if key['Status'] == 'Active':
                # For simplicity, we just flag active access keys to teach you identity tracking
                findings.append({"resource": f"{username} ({key['AccessKeyId']})", "type": "IAM_Access_Key", "issue": "Active API Key Found", "severity": "MEDIUM"})
    return findings
# =========================================================
# STEP 3: AUTOMATED REMEDIATION (Incident Response)
# =========================================================

def fix_security_vulnerabilities(findings):
    print("\n--- [STEP 3] Activating Automated Remediation (Responsive Controls) ---")
    
    if not findings:
        print(" No vulnerabilities found! Environment is fully secure.")
        return

    for issue in findings:
        if issue['severity'] in ['HIGH', 'CRITICAL'] and issue['type'] == 'S3_Bucket':
            bucket_to_fix = issue['resource']
            print(f"🚨 ALERT: Fix triggered for {bucket_to_fix} due to: {issue['issue']}")
            
            # Action: Programmatically shut down public exposure
            # GCP Equivalent: storage_client.get_bucket(b).iam_configuration.public_access_prevention = "enforced"
            s3_client.put_public_access_block(
                Bucket=bucket_to_fix,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"🛡️ REMEDIATED: Public Access has been strictly BLOCKED on bucket: {bucket_to_fix}")

# =========================================================
# MAIN EXECUTION ENGINE
# =========================================================
if __name__ == "__main__":
    print("=======================================================")
    print("    STARTING CLOUD SECURITY COMPLIANCE ENGINE          ")
    print("=======================================================")
    
    # 1. Run the infrastructure setup
    setup_compliance_environment()
    
    # Wait 2 seconds for AWS changes to propagate
    time.sleep(2)
    
    # 2. Scan the account for problems
    detected_issues = run_security_scan()
    print(f"\n[SCAN COMPLETE] Found {len(detected_issues)} security issues.")
    print(json.dumps(detected_issues, indent=2))
    
    # 3. Automatically repair the high threats
    fix_security_vulnerabilities(detected_issues)
    
    print("\n=======================================================")
    print("    EXECUTION FINISHED SUCCESSFULY                     ")
    print("=======================================================")
