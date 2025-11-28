import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

def get_aws_session(aws_access_key, aws_secret_key, region_name='us-east-1'):
    """Initializes and returns a Boto3 session."""
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region_name
        )
        # Test credentials by making a simple API call
        sts = session.client('sts')
        sts.get_caller_identity()
        return session
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS credentials not found or incomplete.")
        return None
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print("Invalid AWS credentials. Please check your access key and secret key.")
        else:
            print(f"An unexpected error occurred: {e}")
        return None

def scan_s3_buckets(session):
    """Scans S3 buckets for public access."""
    s3 = session.client('s3')
    results = {}
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                pba = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                is_public = not (pba['BlockPublicAcls'] and pba['IgnorePublicAcls'] and pba['BlockPublicPolicy'] and pba['RestrictPublicBuckets'])
                results[bucket_name] = 'Public' if is_public else 'Private'
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    results[bucket_name] = 'Public (No Public Access Block)'
                else:
                    results[bucket_name] = f"Error: {e.response['Error']['Code']}"
    except ClientError as e:
        print(f"Error listing S3 buckets: {e}")
    return results

def scan_ec2_instances(session):
    """Scans EC2 instances for security vulnerabilities (e.g., open ports)."""
    ec2 = session.client('ec2')
    results = {}
    try:
        instances = ec2.describe_instances()['Reservations']
        for reservation in instances:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                open_ports = []
                for sg in instance.get('SecurityGroups', []):
                    sg_id = sg['GroupId']
                    sg_details = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                    for perm in sg_details.get('IpPermissions', []):
                        if 'FromPort' in perm and 'ToPort' in perm:
                            port_range = f"{perm['FromPort']}-{perm['ToPort']}"
                            for ip_range in perm.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    open_ports.append(port_range)
                if open_ports:
                    results[instance_id] = f"Open ports: {', '.join(open_ports)}"
                else:
                    results[instance_id] = "No open ports to the internet"
    except ClientError as e:
        print(f"Error scanning EC2 instances: {e}")
    return results

def scan_aws(access_key, secret_key):
    """
    Orchestrates the AWS scan, combines results, and generates a report.
    """
    if access_key == "demo" and secret_key == "demo":
        s3_results = {
            'my-public-bucket': 'Public',
            'my-private-bucket': 'Private',
            'another-public-bucket': 'Public (No Public Access Block)',
        }
        ec2_results = {
            'i-1234567890abcdef0': 'Open ports: 22, 80, 443',
            'i-0987654321fedcba0': 'No open ports to the internet',
        }
    else:
        session = get_aws_session(access_key, secret_key)
        if not session:
            return {
                "score": 0,
                "findings": [{"resource": "AWS Connection", "type": "Authentication", "status": "RISK", "message": "Could not connect to AWS. Check credentials."}],
            }
        s3_results = scan_s3_buckets(session)
        ec2_results = scan_ec2_instances(session)

    findings = []
    
    # Process S3 results
    for bucket, status in s3_results.items():
        is_safe = "private" in status.lower()
        findings.append({
            "resource": bucket,
            "type": "S3",
            "status": "SAFE" if is_safe else "RISK",
            "message": f"Bucket is {status}"
        })

    # Process EC2 results
    for instance, details in ec2_results.items():
        is_safe = "no open ports" in details.lower()
        findings.append({
            "resource": instance,
            "type": "EC2",
            "status": "SAFE" if is_safe else "RISK",
            "message": details
        })

    # Calculate score
    safe_count = len([f for f in findings if f['status'] == 'SAFE'])
    total_count = len(findings)
    score = int((safe_count / total_count) * 100) if total_count > 0 else 100

    return {
        "score": score,
        "findings": findings
    }