package iamrole

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	iamv1beta1 "github.com/ihoegen/iam-role-manager/pkg/apis/iam/v1beta1"
)

//CreateIAMRole creates an IAM role in AWS, based on a spec
func CreateIAMRole(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	roleName := iamRole.ObjectMeta.GetName()
	createRoleOutput, err := iamClient.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: &iamRole.Spec.TrustRelationship,
		Description:              &iamRole.Spec.Description,
		Path:                     &iamRole.Spec.Path,
		RoleName:                 &roleName,
		MaxSessionDuration:       &iamRole.Spec.MaxSessionDuration,
	})
	if err != nil {
		return err
	}
	iamRole.Status.ARN = *createRoleOutput.Role.Arn
	iamRole.Status.RoleID = *createRoleOutput.Role.RoleId
	err = createInlinePolicies(iamClient, iamRole)
	if err != nil {
		return err
	}
	err = attachPolicies(iamClient, iamRole)
	if err != nil {
		return err
	}
	return nil
}

//DeleteIAMRole deletes an IAM role with a matching name
func DeleteIAMRole(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	var errors []error
	roleName := iamRole.ObjectMeta.GetName()
	err := removeInlinePolicies(iamClient, iamRole)
	attachedPolicies, err := iamClient.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return err
	}
	for _, policy := range attachedPolicies.AttachedPolicies {
		_, err = iamClient.DetachRolePolicy(&iam.DetachRolePolicyInput{
			PolicyArn: policy.PolicyArn,
			RoleName:  &roleName,
		})
		if err != nil {
			errors = append(errors, err)
		}
	}
	_, err = iamClient.DeleteRole(&iam.DeleteRoleInput{
		RoleName: &roleName,
	})
	if len(errors) > 0 {
		return fmt.Errorf("Errors occurred while detaching policies: %v", errors)
	}
	return err
}

//SyncIAMRole synchronizes an AWS IAM Role to a spec
func SyncIAMRole(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	var errors []error
	roleName := iamRole.ObjectMeta.GetName()
	_, err := iamClient.UpdateRole(&iam.UpdateRoleInput{
		Description:        &iamRole.Spec.Description,
		MaxSessionDuration: &iamRole.Spec.MaxSessionDuration,
		RoleName:           &roleName,
	})
	if err != nil {
		return err
	}
	_, err = iamClient.UpdateAssumeRolePolicy(&iam.UpdateAssumeRolePolicyInput{
		RoleName:       &roleName,
		PolicyDocument: &iamRole.Spec.TrustRelationship,
	})
	err = removeInlinePolicies(iamClient, iamRole)
	if err != nil {
		return err
	}
	err = createInlinePolicies(iamClient, iamRole)
	if err != nil {
		return err
	}
	err = attachPolicies(iamClient, iamRole)
	if err != nil {
		errors = append(errors, err)
	}
	attachedPolicies, err := iamClient.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return err
	}
	for _, policy := range attachedPolicies.AttachedPolicies {
		if !in(iamRole.Spec.Policies, *policy.PolicyArn) && !in(iamRole.Spec.Policies, *policy.PolicyName) {
			_, err = iamClient.DetachRolePolicy(&iam.DetachRolePolicyInput{
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

// Checks to see if a named IAM Role exists in AWS
// TODO: Enhance the logic
func iamRoleExists(iamClient *iam.IAM, roleName string) bool {
	_, err := iamClient.GetRole(&iam.GetRoleInput{
		RoleName: &roleName,
	})
	return err == nil
}

// Attaches policies found in the spec to a named IAM role
func attachPolicies(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	roleName := iamRole.ObjectMeta.GetName()
	var errors []error
	for _, policy := range iamRole.Spec.Policies {
		policyArn, err := getArn(policy)
		if err != nil {
			return err
		}
		_, err = iamClient.AttachRolePolicy(&iam.AttachRolePolicyInput{
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
func createInlinePolicies(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	var errors []error
	roleName := iamRole.ObjectMeta.GetName()
	for _, inlinePolicy := range iamRole.Spec.InlinePolicy {
		_, err := iamClient.PutRolePolicy(&iam.PutRolePolicyInput{
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

// Removes inline policies from a role
func removeInlinePolicies(iamClient *iam.IAM, iamRole *iamv1beta1.IAMRole) error {
	var errors []error
	roleName := iamRole.ObjectMeta.GetName()
	currentPolicies, err := iamClient.ListRolePolicies(&iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return err
	}
	for _, policy := range currentPolicies.PolicyNames {
		_, err = iamClient.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
			PolicyName: policy,
			RoleName:   &roleName,
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
// TODO: Enhance the logic
func isArn(policy string) bool {
	return strings.Contains(policy, "arn:aws:iam")
}
