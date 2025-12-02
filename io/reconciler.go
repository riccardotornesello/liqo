package main

import (
	"context"
	"fmt"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	configuration "github.com/liqotech/liqo/pkg/liqo-controller-manager/networking/external-network/configuration"
	"github.com/liqotech/liqo/pkg/virtualKubelet/forge"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type TestReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
}

func NewTestReconciler(cl client.Client, s *runtime.Scheme) *TestReconciler {
	return &TestReconciler{
		Client: cl,
		Scheme: s,
	}
}

func (r *TestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("-----------------------------")

	conf := &networkingv1beta1.Configuration{}
	if err := r.Client.Get(ctx, req.NamespacedName, conf); err != nil {
		if errors.IsNotFound(err) {
			klog.Infof("There is no configuration %s", req.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get the configuration %q: %w", req.NamespacedName, err)
	}
	klog.Infof("Reconciling configuration %q", req.NamespacedName)

	remoteClusterID, err := getConfigurationRemoteClusterID(conf)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get remote cluster ID for configuration %q: %w", req.NamespacedName, err)
	}
	klog.Infof("Configuration %q refers to remote cluster %q", req.NamespacedName, remoteClusterID)

	// Get the pods coming from the remote cluster.
	podList := &corev1.PodList{}
	if err := r.Client.List(ctx, podList, client.MatchingLabels{
		forge.LiqoOriginClusterIDKey: remoteClusterID,
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to list pods: %w", err)
	}

	destinationPodIps := make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Status.PodIP != "" {
			destinationPodIps = append(destinationPodIps, pod.Status.PodIP)
		}
	}

	// Get the pods offloaded to the remote cluster: filter the pods by node name.
	podList = &corev1.PodList{}
	if err := r.Client.List(ctx, podList, client.MatchingLabels{
		consts.LocalPodLabelKey: consts.LocalPodLabelValue,
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to list pods: %w", err)
	}

	sourcePodIps := make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Spec.NodeName == remoteClusterID && pod.Status.PodIP != "" {
			sourcePodIps = append(sourcePodIps, pod.Status.PodIP)
		}
	}

	// Reconcile the gateway FirewallConfiguration.
	if err := createOrUpdateGatewayConfiguration(ctx, r.Client, conf, sourcePodIps, destinationPodIps); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create or update gateway configuration for configuration %q: %w", req.NamespacedName, err)
	}

	// Reconcile the fabric FirewallConfiguration.
	if err := createOrUpdateFabricConfiguration(ctx, r.Client, conf, destinationPodIps); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create or update fabric configuration for configuration %q: %w", req.NamespacedName, err)
	}

	klog.Infof("Reconciliation of configuration %q completed", req.NamespacedName)

	return ctrl.Result{}, nil
}

func (r *TestReconciler) podEnqueuer(ctx context.Context, obj client.Object) []ctrl.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		klog.Errorf("Expected a Pod object but got %T", obj)
		return nil
	}

	labels := pod.GetLabels()
	localPod, exists := labels[consts.LocalPodLabelKey]
	if !exists || localPod != consts.LocalPodLabelValue {
		return nil
	}

	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return nil
	}

	klog.Infof("Enqueuing Configuration for Pod %s on Node %s", pod.Name, nodeName)
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: nodeName, Namespace: forgeNamespaceName(nodeName)}}}
}

func (r *TestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	filterByLabelsPredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			configuration.Configured: configuration.ConfiguredValue,
		},
	})
	if err != nil {
		return err
	}

	return ctrl.
		NewControllerManagedBy(mgr).
		For(&networkingv1beta1.Configuration{}, builder.WithPredicates(filterByLabelsPredicate)).
		Owns(&networkingv1beta1.FirewallConfiguration{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.podEnqueuer)).
		Complete(r)
}
