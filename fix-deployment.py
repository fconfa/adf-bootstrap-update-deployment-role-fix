import boto3, json

# Create IAM client
iam = boto3.client('iam')

# Role and policy details
deployment_account_id = 423623863573
role_name = 'adf-bootstrap-update-deployment-role'
policy_name = 'limited-update-permissions-only'

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

try:
    response = iam.get_role_policy(
        RoleName=role_name,
        PolicyName=policy_name
    )
    
    # Load the existing policy document and add the new statement
    policy_document = response['PolicyDocument']
    policy_document['Statement'].append(new_statement)

    # Update the inline policy
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document)
    )
    
    print(f"Successfully updated policy '{policy_name}' of role '{role_name}'.")
    
except iam.exceptions.NoSuchEntityException:
    print(f"The policy '{policy_name}' does not exist for the role '{role_name}'. Please check the role and policy name.")
except Exception as e:
    print(f"An error occurred: {e}")
