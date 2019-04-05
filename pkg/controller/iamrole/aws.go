package iamrole

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	iamv1beta1 "github.com/ihoegen/iam-role-manager/pkg/apis/iam/v1beta1"
)

// IAMClient provides an interface with interacting with AWS
type IAMClient struct {
	Client *iam.IAM
	Role   *iamv1beta1.IAMRole
}

// NewIAMClient returns a new client for interacting with AWS IAM
func NewIAMClient(client *iam.IAM, role *iamv1beta1.IAMRole) IAMClient {
	return IAMClient{
		Client: client,
		Role:   role,
	}
}

//CreateIAMRole creates an IAM role in AWS, based on a spec
func (i *IAMClient) CreateIAMRole() error {
	roleName := i.Role.ObjectMeta.GetName()
	createRoleOutput, err := i.Client.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: &i.Role.Spec.TrustRelationship,
		Description:              &i.Role.Spec.Description,
		Path:                     &i.Role.Spec.Path,
		RoleName:                 &roleName,
		MaxSessionDuration:       &i.Role.Spec.MaxSessionDuration,
	})
	if err != nil {
		return err
	}
	i.Role.Status.ARN = *createRoleOutput.Role.Arn
	i.Role.Status.RoleID = *createRoleOutput.Role.RoleId
	err = i.createInlinePolicies()
	if err != nil {
		return err
	}
	err = i.attachPolicies()
	if err != nil {
		return err
	}
	return nil
}

//DeleteIAMRole deletes an IAM role
func (i *IAMClient) DeleteIAMRole() error {
	roleName := i.Role.ObjectMeta.GetName()
	currentPolicies, err := i.listInlinePolicies(roleName)
	if err != nil {
		return err
	}
	for _, policy := range currentPolicies {
		_, err = i.Client.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
			PolicyName: &policy,
			RoleName:   &roleName,
		})
		if err != nil {
			return err
		}
	}
	attachedPolicies, err := i.listAttachedPolicies(roleName)
	if err != nil {
		return err
	}
	for _, policy := range attachedPolicies {
		_, err = i.Client.DetachRolePolicy(&iam.DetachRolePolicyInput{
			PolicyArn: policy.PolicyArn,
			RoleName:  &roleName,
		})
		if err != nil {
			return err
		}
	}
	_, err = i.Client.DeleteRole(&iam.DeleteRoleInput{
		RoleName: &roleName,
	})
	return err
}

//SyncIAMRole synchronizes an AWS IAM Role to a spec
func (i *IAMClient) SyncIAMRole() error {
	var errors []error
	roleName := i.Role.ObjectMeta.GetName()
	getRoleOutput, err := i.Client.GetRole(&iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return err
	}
	awsRole := *getRoleOutput.Role
	if *awsRole.Description != i.Role.Spec.Description {
		_, err = i.Client.UpdateRoleDescription(&iam.UpdateRoleDescriptionInput{
			Description: &i.Role.Spec.Description,
			RoleName:    &roleName,
		})
		if err != nil {
			return err
		}
	}
	if *awsRole.MaxSessionDuration != i.Role.Spec.MaxSessionDuration {
		_, err = i.Client.UpdateRole(&iam.UpdateRoleInput{
			RoleName:           &roleName,
			MaxSessionDuration: &i.Role.Spec.MaxSessionDuration,
		})
		if err != nil {
			return err
		}
	}
	if *awsRole.AssumeRolePolicyDocument != i.Role.Spec.TrustRelationship {
		_, err = i.Client.UpdateAssumeRolePolicy(&iam.UpdateAssumeRolePolicyInput{
			RoleName:       &roleName,
			PolicyDocument: &i.Role.Spec.TrustRelationship,
		})
		if err != nil {
			return err
		}
	}
	err = i.createInlinePolicies()
	if err != nil {
		return err
	}
	inlinePolicies, err := i.listInlinePolicies(roleName)
	if err != nil {
		return err
	}
	var requestedInlinePolicies []string
	for _, p := range i.Role.Spec.InlinePolicy {
		requestedInlinePolicies = append(requestedInlinePolicies, p.Name)
	}
	for _, policy := range inlinePolicies {
		if !in(requestedInlinePolicies, policy) {
			_, err = i.Client.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
				PolicyName: &policy,
				RoleName:   &roleName,
			})
			if err != nil {
				errors = append(errors, err)
			}
		}
	}
	err = i.attachPolicies()
	if err != nil {
		errors = append(errors, err)
	}
	attachedPolicies, err := i.listAttachedPolicies(roleName)
	if err != nil {
		return err
	}
	for _, policy := range attachedPolicies {
		if !in(i.Role.Spec.Policies, *policy.PolicyArn) && !in(i.Role.Spec.Policies, *policy.PolicyName) {
			_, err = i.Client.DetachRolePolicy(&iam.DetachRolePolicyInput{
				PolicyArn: policy.PolicyArn,
				RoleName:  &roleName,
			})
			if err != nil {
				errors = append(errors, err)
			}
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("Errors occurred while detaching policies: %v", errors)
	}
	return nil
}

// IAMRoleExists Checks to see if a named IAM Role exists in AWS
func (i *IAMClient) IAMRoleExists(roleName string) bool {
	_, err := i.Client.GetRole(&iam.GetRoleInput{
		RoleName: &roleName,
	})
	return err == nil
}

// Attaches policies found in the spec to a named IAM role
func (i *IAMClient) attachPolicies() error {
	roleName := i.Role.ObjectMeta.GetName()
	var errors []error
	for _, policy := range i.Role.Spec.Policies {
		policyArn, err := getArn(policy)
		if err != nil {
			return err
		}
		_, err = i.Client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: &policyArn,
			RoleName:  &roleName,
		})
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("Errors occurred while attaching policies: %v", errors)
	}
	return nil
}

// Creates inline polices defined in a spec and attaches it to a role
func (i *IAMClient) createInlinePolicies() error {
	var errors []error
	roleName := i.Role.ObjectMeta.GetName()
	for _, inlinePolicy := range i.Role.Spec.InlinePolicy {
		_, err := i.Client.PutRolePolicy(&iam.PutRolePolicyInput{
			PolicyDocument: &inlinePolicy.Value,
			RoleName:       &roleName,
			PolicyName:     &inlinePolicy.Name,
		})
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("Errors occurred while attaching policies: %v", errors)
	}
	return nil
}

// Returns the ARN of a policy; allows for simply naming policies
func getArn(policyName string) (string, error) {
	if isArn(policyName) {
		return policyName, nil
	}
	stsClient := sts.New(session.New())
	callerIdentity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("arn:aws:iam::%s:policy/%s", *callerIdentity.Account, policyName), nil
}

// Returns if a policy string is an ARN
func isArn(policy string) bool {
	return strings.Contains(policy, "arn:aws:iam")
}

// Paginate over inline policies
func (i *IAMClient) listInlinePolicies(roleName string) ([]string, error) {
	var policyNamesPointers []*string
	currentPolicies, err := i.Client.ListRolePolicies(&iam.ListRolePoliciesInput{
			RoleName: &roleName,
		})
		if err != nil {
			return nil, err
		}
		isTruncated := *currentPolicies.IsTruncated
		if isTruncated == true {
        policyNamesPointers = append(policyNamesPointers, currentPolicies.PolicyNames...)
        marker := *currentPolicies.Marker
        for isTruncated {
            currentPolicies, err := i.Client.ListRolePolicies(&iam.ListRolePoliciesInput{
            RoleName: &roleName,
            Marker:   &marker,
            })
						if err != nil {
							return nil, err
						}
            policyNamesPointers = append(policyNamesPointers, currentPolicies.PolicyNames...)
            isTruncated = *currentPolicies.IsTruncated
            if isTruncated == true {
                marker = *currentPolicies.Marker
            }
					}
	    } else {
	        currentPolicies, err := i.Client.ListRolePolicies(&iam.ListRolePoliciesInput{
	            RoleName: &roleName,
	        })
					if err != nil {
						return nil, err
					}
	        policyNamesPointers = append(policyNamesPointers, currentPolicies.PolicyNames...)
	    }
	var policyNameValues []string
	for _, val := range policyNamesPointers {
		policyNameValues = append(policyNameValues, *val)
	}
	return policyNameValues, nil
}

// Paginate over attached policies
func (i *IAMClient) listAttachedPolicies(roleName string) ([]iam.AttachedPolicy, error) {
	var policyPointers []*iam.AttachedPolicy
	currentPolicies, err := i.Client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
		})
		if err != nil {
			return nil, err
		}
		isTruncated := *currentPolicies.IsTruncated
		if isTruncated == true {
				policyPointers = append(policyPointers, currentPolicies.AttachedPolicies...)
				marker := *currentPolicies.Marker
				for isTruncated {
						currentPolicies, err := i.Client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
						RoleName: &roleName,
						Marker:   &marker,
						})
						if err != nil {
							return nil, err
						}
						policyPointers = append(policyPointers, currentPolicies.AttachedPolicies...)
						isTruncated = *currentPolicies.IsTruncated
						if isTruncated == true {
								marker = *currentPolicies.Marker
						}
					}
			} else {
					currentPolicies, err := i.Client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
							RoleName: &roleName,
					})
					if err != nil {
						return nil, err
					}
					policyPointers = append(policyPointers, currentPolicies.AttachedPolicies...)
			}
	var policyNameValues []iam.AttachedPolicy
	for _, val := range policyPointers {
		policyNameValues = append(policyNameValues, *val)
	}
	return policyNameValues, nil
}
