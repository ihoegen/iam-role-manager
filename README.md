# IAM Role CRD
Use Kubernetes specs to create IAM Roles in AWS

## Installation

To install to the clusters, you can either use kustomize 

```
kubectl apply -f config/crds
kustomize build config/default | kubectl apply -f -
```

Or use helm

```
helm install deploy/iam-role-manager
```


### Required Permissions

```
iam:AttachRolePolicy
iam:CreateRole
iam:DeleteRole
iam:DeleteRolePolicy
iam:DetachRolePolicy
iam:GetRole
iam:ListAttachedRolePolicies
iam:ListRolePolicies
iam:PutRolePolicy
iam:UpdateAssumeRolePolicy
iam:UpdateRole
sts:GetCallerIdentity
```

## Usage

Below is a sample AWS role, with the name sample-role

```yaml
apiVersion: iam.amazonaws.com/v1beta1
kind: IAMRole
metadata:
  labels:
    controller-tools.k8s.io: "1.0"
  name: sample-role
spec:
  description: "Role description"
  trustRelationship: |
    {
        "Version": "2012-10-17",
        "Statement": [
            {i
                "Effect": "Allow",
                "Principal": {
                    "AWS": "ec2.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
  inlinePolicy: 
  - name: sample-inline
    value: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": "ec2:Describe*",
            "Resource": "*"
          }
        ]
      }
  policies: []
  path: "/"
  maxSessionDuration: 3600
```