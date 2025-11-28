import sys
import os
from colorama import Fore, Style, init

# Adjusting the path to include the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_engine.aws_scanner import get_aws_session, scan_s3_buckets, scan_ec2_instances

# Initialize Colorama
init(autoreset=True)

def main():
    """Main function for the CLI application."""
    print(Fore.CYAN + Style.BRIGHT + "Welcome to CloudSentinel - AWS Security Scanner" + Style.RESET_ALL)

    aws_access_key = input("Enter your AWS Access Key ID: ").strip()
    aws_secret_key = input("Enter your AWS Secret Access Key: ").strip()
    region_name = input("Enter your AWS Region (e.g., us-east-1): ").strip()

    session = get_aws_session(aws_access_key, aws_secret_key, region_name)

    if session:
        print(Fore.GREEN + "\nSuccessfully connected to AWS.")
        
        while True:
            print(Fore.YELLOW + "\nSelect a scan to perform:")
            print("1. Scan S3 Buckets")
            print("2. Scan EC2 Instances")
            print("3. Exit")
            choice = input("Enter your choice (1-3): ").strip()

            if choice == '1':
                print("\nScanning S3 buckets...")
                s3_results = scan_s3_buckets(session)
                if s3_results:
                    print(Fore.GREEN + "S3 Scan Results:")
                    for bucket, status in s3_results.items():
                        print(f"- {bucket}: {status}")
                else:
                    print(Fore.YELLOW + "No S3 buckets found or an error occurred.")
            
            elif choice == '2':
                print("\nScanning EC2 instances...")
                ec2_results = scan_ec2_instances(session)
                if ec2_results:
                    print(Fore.GREEN + "EC2 Scan Results:")
                    for instance, details in ec2_results.items():
                        print(f"- {instance}: {details}")
                else:
                    print(Fore.YELLOW + "No EC2 instances found or an error occurred.")

            elif choice == '3':
                print(Fore.CYAN + "Exiting CloudSentinel. Goodbye!")
                break
            
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
    else:
        print(Fore.RED + "Failed to connect to AWS. Please check your credentials and permissions.")

if __name__ == "__main__":
    main()
