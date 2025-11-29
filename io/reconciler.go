package main

import (
	"context"
	"fmt"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	networkingv1beta1firewall "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/firewall"
	configuration "github.com/liqotech/liqo/pkg/liqo-controller-manager/networking/external-network/configuration"
	tenantnamespace "github.com/liqotech/liqo/pkg/tenantNamespace"
	"github.com/liqotech/liqo/pkg/utils/resource"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// gatewayResourceNamePrefix is the prefix used for naming gateway FirewallConfiguration resources.
	gatewayResourceNamePrefix = "security-gateway"

	// gatewayTableName is the name of the firewall table used by the gateway FirewallConfiguration.
	gatewayTableName = "cluster-security"

	// firewallCategoryTargetValueGw is the value used by the securityconfiguration controller to reconcile only resources related to a gateway.
	firewallCategoryTargetValueGw = "gateway"

	// firewallSubCategoryTargetValueSecurity is the value used by the securityconfiguration controller to reconcile only resources related to the IP mapping.
	firewallSubCategoryTargetValueSecurity = "security"
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

	// Get the pods hosted on the node associated with this configuration.
	podList := &corev1.PodList{}
	if err := r.Client.List(ctx, podList, client.MatchingLabels{
		consts.LocalPodLabelKey: consts.LocalPodLabelValue,
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to list pods: %w", err)
	}

	podsInCluster := []*corev1.Pod{}
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Spec.NodeName == remoteClusterID {
			podsInCluster = append(podsInCluster, pod)
		}
	}

	klog.Infof("Found %d pods on node %s", len(podsInCluster), remoteClusterID)

	// Just for testing purposes, we log the names of the pods found.
	for _, pod := range podsInCluster {
		klog.Infof("Pod %s/%s is hosted on node %s", pod.Namespace, pod.Name, remoteClusterID)
	}

	if err := createOrUpdateGatewayConfiguration(ctx, r.Client, conf); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create or update gateway configuration for configuration %q: %w", req.NamespacedName, err)
	}

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

func forgeNamespaceName(clusterID string) string {
	return fmt.Sprintf("%s-%s", tenantnamespace.NamePrefix, clusterID)
}

func forgeGatewayResourceName(clusterID string) string {
	return fmt.Sprintf("%s-%s", gatewayResourceNamePrefix, clusterID)
}

func forgeGatewayLabels(clusterID string) map[string]string {
	return map[string]string{
		firewall.FirewallCategoryTargetKey:    firewallCategoryTargetValueGw,
		firewall.FirewallSubCategoryTargetKey: firewallSubCategoryTargetValueSecurity,
		firewall.FirewallUniqueTargetKey:      string(clusterID),
	}
}

func forgeGatewaySpec() *networkingv1beta1.FirewallConfigurationSpec {
	return &networkingv1beta1.FirewallConfigurationSpec{
		Table: networkingv1beta1firewall.Table{
			Name:   ptr.To(gatewayTableName),
			Family: ptr.To(networkingv1beta1firewall.TableFamilyIPv4),
			Chains: []networkingv1beta1firewall.Chain{},
		},
	}
}

func getConfigurationRemoteClusterID(cfg *networkingv1beta1.Configuration) (string, error) {
	remoteClusterID, ok := cfg.Labels[string(consts.RemoteClusterID)]
	if !ok {
		return "", fmt.Errorf("configuration %q has no remote cluster ID label", cfg.Name)
	}
	return remoteClusterID, nil
}

func createOrUpdateGatewayConfiguration(ctx context.Context, cl client.Client, cfg *networkingv1beta1.Configuration) error {
	remoteClusterID, err := getConfigurationRemoteClusterID(cfg)
	if err != nil {
		return err
	}

	fwcfg := &networkingv1beta1.FirewallConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      forgeGatewayResourceName(remoteClusterID),
			Namespace: forgeNamespaceName(remoteClusterID),
		},
	}

	klog.Infof("Creating firewall configuration %q for %q", fwcfg.Name, remoteClusterID)

	if _, err := resource.CreateOrUpdate(
		ctx, cl, fwcfg,
		mutateGatewayConfiguration(fwcfg, cfg),
	); err != nil {
		return err
	}

	klog.Infof("Firewall configuration %q for %q created", fwcfg.Name, remoteClusterID)

	return nil
}

func mutateGatewayConfiguration(fwcfg *networkingv1beta1.FirewallConfiguration, cfg *networkingv1beta1.Configuration) func() error {
	return func() error {
		if cfg.Labels == nil {
			return fmt.Errorf("configuration %q has no labels", cfg.Name)
		}

		remoteClusterID, err := getConfigurationRemoteClusterID(cfg)
		if err != nil {
			return err
		}

		fwcfg.SetLabels(forgeGatewayLabels(remoteClusterID))
		fwcfg.Spec = *forgeGatewaySpec()
		return controllerutil.SetOwnerReference(cfg, fwcfg, scheme)
	}
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
