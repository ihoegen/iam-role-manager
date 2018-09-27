/*
Copyright 2018 Ian Hoegen.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package iamrole

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	iamv1beta1 "github.com/ihoegen/iam-role-manager/pkg/apis/iam/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var eventRecorder record.EventRecorder

// Add creates a new IAMRole Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	log.Println("IAMRole controller added")
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileIAMRole{Client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("iamrole-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to IAMRole
	err = c.Watch(&source.Kind{Type: &iamv1beta1.IAMRole{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}
	eventRecorder = mgr.GetRecorder("iamrole")
	return nil
}

var _ reconcile.Reconciler = &ReconcileIAMRole{}

// ReconcileIAMRole reconciles a IAMRole object
type ReconcileIAMRole struct {
	client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a IAMRole object and makes changes based on the state read
// and what is in the IAMRole.Spec
// Automatically creates IAM roles in AWS
// +kubebuilder:rbac:groups=iam.amazonaws.com,resources=iamroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch;delete
func (r *ReconcileIAMRole) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the IAMRole instance
	iamRole := &iamv1beta1.IAMRole{}
	iamClient := iam.New(session.New())
	err := r.Get(context.TODO(), request.NamespacedName, iamRole)
	if err != nil {
		// IAM role deleted
		if errors.IsNotFound(err) {
			iamRole.ObjectMeta.SetName(request.Name)
			err = DeleteIAMRole(iamClient, iamRole)
			return reconcile.Result{}, err
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	// IAM Role exists in AWS; updating
	if iamRoleExists(iamClient, iamRole.ObjectMeta.GetName()) {
		err = SyncIAMRole(iamClient, iamRole)
		if err != nil {
			eventRecorder.Event(iamRole, "Warning", "ErrorSyncingIAMRole", err.Error())
			return reconcile.Result{}, err
		}
		eventRecorder.Event(iamRole, "Normal", "IAMRoleUpdated", "Successfully updated IAM role")
		return reconcile.Result{}, nil
	}
	// IAM Role doesn't exist in AWS; creating
	err = CreateIAMRole(iamClient, iamRole)
	if err != nil {
		eventRecorder.Event(iamRole, "Warning", "ErrorCreatingIAMRole", err.Error())
		return reconcile.Result{}, err
	}
	err = r.Update(context.TODO(), iamRole)
	eventRecorder.Event(iamRole, "Normal", "IAMRoleCreated", "Successfully created IAM role")
	return reconcile.Result{}, err

}
