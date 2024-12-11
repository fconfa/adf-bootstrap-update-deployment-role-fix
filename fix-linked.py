'''Fix the adf-bootstrap-update-deployment-role permissions after upgrade to ADF 4.0.0

The default role policy distributed with ADF 4.0.0 is missing some permissions and this causes the bootstrap pipeline to fail.
This script will iterate on ALL linked accounts in an AWS Organization (except those under the OUs listed in excluded_ou_ids) and update the role policy.
Run this script from the management account. Add the 'fix' parameter to actually perform the update.

NOTE: This script will only check if the role policy contains a valid statemente with the iam:PassRole action allowed on all resources and may not work correctly if the role policy created by ADF 4.0.0 has been modified from the factory version.

author: f.confalonieri@crif.com
date: 2024-12-11
'''
import sys
import boto3
import json

root_id = '<add root id>'
excluded_ou_ids = ['<mgmt OU id>', '<deployment OU id>', '<suspended OU id>']  # management, deployment, suspended, ...

assume_role_name = 'OrganizationAccountAccessRole'
fix_role_name = 'adf-bootstrap-update-deployment-role'
fix_inline_policy_name = 'allow-updates-to-bootstrap-stacks'

# Define the new statement to be added to the inline policy
new_statement = {
    "Effect": "Allow",
    "Action": [
        "iam:PassRole",
        "iam:ListPolicyVersions",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:GetPolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:PutRolePolicy",
        "codebuild:BatchGetProjects"
    ],
    "Resource": "*"
}

org_client = boto3.client('organizations')
sts_client = boto3.client('sts')

# Assume role in target account and return credentials
def assume_role(account_id):
    role_arn = f"arn:aws:iam::{account_id}:role/{assume_role_name}"
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"SessionForAccount_{account_id}"
        )
        return response['Credentials']
    except Exception as e:
        print(f"{account_id}: Error assuming {assume_role_name} role: {e}")
        return None

# Check if the policy exists in the role and has the iam:PassRole action
def fix_policy(credentials, account_id, fix):
    # Assume role with the provided credentials
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    try:
        # Check if the role exists
        roles = iam_client.list_roles()
        role_exists = False
        for role in roles['Roles']:
            if role['RoleName'] == fix_role_name:
                role_exists = True
                break
        
        if not role_exists:
            print(f"Role '{fix_role_name}' does not exist in account {account_id}.")
            return False
        
        # Check if the role has the correct inline policy
        policy_names = iam_client.list_role_policies(RoleName=fix_role_name)['PolicyNames']
        
        if fix_inline_policy_name not in policy_names:
            print(f"{account_id}: Role '{fix_role_name}' does not contains inline policy '{fix_inline_policy_name}'.")
            return False
        
        # Get the policy document to check the permissions
        policy_document = iam_client.get_role_policy(
            RoleName=fix_role_name,
            PolicyName=fix_inline_policy_name
        )['PolicyDocument']
        
        # Check if the policy contains the required statement
        for statement in policy_document['Statement']:
            if (statement['Effect'] == 'Allow' and
                'iam:PassRole' in statement['Action'] and
                '*' in statement['Resource']):
                print(f"{account_id}: Role '{fix_role_name}' already has the correct policy.")
                return False


        if fix:
            # Update the inline policy
            policy_document['Statement'].append(new_statement)
            iam_client.put_role_policy(
                RoleName=fix_role_name,
                PolicyName=fix_inline_policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            print(f"{account_id}: Successfully updated policy '{fix_inline_policy_name}'")
        else:
            print(f"{account_id}: Role '{fix_role_name}' does not have the correct policy and must be updated")

        return True

    except Exception as e:
        print(f"{account_id}: Error updating role policy in account: {e}")
        return False

# Recursively retrieve all accounts in the given OU
def get_accounts_in_ou(ou_id):
    accounts_in_ou = []

    # Get accounts in the current OU
    accounts_response = org_client.list_accounts_for_parent(ParentId=ou_id)
    accounts_in_ou.extend(accounts_response['Accounts'])

    # Get child OUs for the current OU
    child_ou_response = org_client.list_organizational_units_for_parent(ParentId=ou_id)
    
    for ou in child_ou_response['OrganizationalUnits']:
        accounts_in_ou.extend(get_accounts_in_ou(ou['Id']))
    
    return accounts_in_ou

# Fix the role's policy across all accounts
def fix_roles_in_all_accounts(fix):
    total_fixed = 0

    try:
        # Get the list of all OUs in the organization (including root)
        ou_response = org_client.list_organizational_units_for_parent(ParentId=root_id)  # Replace with the root ID or a specific parent OU ID

        for ou in ou_response['OrganizationalUnits']:
            ou_id = ou['Id']
            ou_name = ou['Name']

            # Skip excluded OUs
            if ou_id in excluded_ou_ids:
                print(f"Skipping OU '{ou_name}' as it's in the excluded list.")
                continue

            print(f"Checking OU: {ou_name}")

            # Get all accounts in this OU (including nested OUs)
            accounts_in_ou = get_accounts_in_ou(ou_id)

            for account in accounts_in_ou:
                account_id = account['Id']

                # Assume the role in the target account
                credentials = assume_role(account_id)
                if credentials:
                    # Check if the role exists and if the policy contains the required statement
                    if fix_policy(credentials, account_id, fix):
                        total_fixed += 1

        print(f"Total accounts {'to be ' if not fix else ''}fixed: {total_fixed}")

    except Exception as e:
        print(f"Error fetching accounts or checking roles: {e}")

# Run the main function
fix=False
if (len(sys.argv) > 1) and (sys.argv[1] == 'fix'):
    fix=True
fix_roles_in_all_accounts(fix)