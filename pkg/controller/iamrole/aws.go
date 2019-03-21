package iamrole

import (
	"fmt"
	"log"
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
	log.Printf("Created role: %+v\n", createRoleOutput)
	if err != nil {
		log.Printf("Error creating role: %+v\n", err)
		return err
	}
	i.Role.Status.ARN = *createRoleOutput.Role.Arn
	i.Role.Status.RoleID = *createRoleOutput.Role.RoleId
	err = i.createInlinePolicies()
	if err != nil {
		log.Printf("Error creating inline policies: %+v\n", err)
		return err
	}
	err = i.attachPolicies()
	if err != nil {
		log.Printf("Error attaching policies: %+v\n", err)
		return err
	}
	return nil
}

//DeleteIAMRole deletes an IAM role
func (i *IAMClient) DeleteIAMRole() error {
	roleName := i.Role.ObjectMeta.GetName()
	currentPolicies, err := i.listInlinePolicies(roleName)
	if err != nil {
		log.Printf("Error listing inline policies: %+v\n", err)
		return err
	}
	for _, policy := range currentPolicies {
		_, err = i.Client.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
			PolicyName: &policy,
			RoleName:   &roleName,
		})
		if err != nil {
			log.Printf("Error deleting role policy: %+v\n", err)
			return err
		}
	}
	attachedPolicies, err := i.listAttachedPolicies(roleName)
	if err != nil {
		log.Printf("Error listing attached policies: %+v\n", err)
		return err
	}
	for _, policy := range attachedPolicies {
		_, err = i.Client.DetachRolePolicy(&iam.DetachRolePolicyInput{
			PolicyArn: policy.PolicyArn,
			RoleName:  &roleName,
		})
		if err != nil {
			log.Printf("Error detaching policies: %+v\n", err)
			return err
		}
	}
	_, err = i.Client.DeleteRole(&iam.DeleteRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		log.Printf("Error deleting role: %+v\n", err)
	}
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

func (i *IAMClient) innerListInlinePolicies(roleName, m string) (policies []*string, isTruncated bool, marker string, err error) {
	var input *iam.ListRolePoliciesInput
	if m != "" {
		input = &iam.ListRolePoliciesInput{
			RoleName: &roleName,
			Marker:   &m,
		}
	} else {
		input = &iam.ListRolePoliciesInput{
			RoleName: &roleName,
		}
	}
	currentPolicies, err := i.Client.ListRolePolicies(input)
	if err != nil {
		return nil, false, "", err
	}
	isTruncated = *currentPolicies.IsTruncated
	if isTruncated {
		marker = *currentPolicies.Marker
	}
	return currentPolicies.PolicyNames, isTruncated, marker, nil
}

// Paginate over inline policies
func (i *IAMClient) listInlinePolicies(roleName string) ([]string, error) {
	var policyNamesPointers []*string
	var policies []*string
	var isTruncated bool
	var marker string
	var err error
	// First pass through will tell us if there are more policies we need to fetch.
	// If we don't do it this way, we will get a "ValidationError: Invalid Marker"
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#ListRolePoliciesInput
	policies, isTruncated, marker, err = i.innerListInlinePolicies(roleName, "")
	if err != nil {
		return nil, err
	}
	policyNamesPointers = append(policyNamesPointers, policies...)

	for isTruncated {
		policies, isTruncated, marker, err = i.innerListInlinePolicies(roleName, marker)
		if err != nil {
			return nil, err
		}
		policyNamesPointers = append(policyNamesPointers, policies...)
	}

	var policyNameValues []string
	for _, val := range policyNamesPointers {
		policyNameValues = append(policyNameValues, *val)
	}
	return policyNameValues, nil
}

func (i *IAMClient) innerListAttachedPolicies(roleName, m string) (policies []*iam.AttachedPolicy, isTruncated bool, marker string, err error) {
	var input *iam.ListAttachedRolePoliciesInput
	if m != "" {
		input = &iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
			Marker:   &m,
		}
	} else {
		input = &iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
		}
	}
	currentPolicies, err := i.Client.ListAttachedRolePolicies(input)
	if err != nil {
		return nil, false, "", err
	}
	isTruncated = *currentPolicies.IsTruncated
	if isTruncated {
		marker = *currentPolicies.Marker
	}
	return currentPolicies.AttachedPolicies, isTruncated, marker, nil
}

// Paginate over attached policies
func (i *IAMClient) listAttachedPolicies(roleName string) ([]iam.AttachedPolicy, error) {
	var policyPointers []*iam.AttachedPolicy
	var policies []*iam.AttachedPolicy
	var isTruncated bool
	var marker string
	var err error

	// First pass through will tell us if there are more policies we need to fetch.
	// If we don't do it this way, we will get a "ValidationError: Invalid Marker"
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#ListRolePoliciesInput
	policies, isTruncated, marker, err = i.innerListAttachedPolicies(roleName, "")
	if err != nil {
		return nil, err
	}
	policyPointers = append(policyPointers, policies...)

	for isTruncated {
		policies, isTruncated, marker, err = i.innerListAttachedPolicies(roleName, marker)
		if err != nil {
			return nil, err
		}
		policyPointers = append(policyPointers, policies...)
	}
	var policyNameValues []iam.AttachedPolicy
	for _, val := range policyPointers {
		policyNameValues = append(policyNameValues, *val)
	}
	return policyNameValues, nil
}
