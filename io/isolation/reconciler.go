package isolation

import (
	"context"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/virtualKubelet/forge"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type IsolationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func NewIsolationReconciler(cl client.Client, s *runtime.Scheme) *IsolationReconciler {
	return &IsolationReconciler{
		Client: cl,
		Scheme: s,
	}
}

func (r *IsolationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Get all the configurations
	var configList networkingv1beta1.ConfigurationList
	if err := r.List(ctx, &configList); err != nil {
		return ctrl.Result{}, err
	}

	// Get all the pods
	var podList corev1.PodList
	if err := r.List(ctx, &podList, client.MatchingLabels{consts.ManagedByLabelKey: consts.ManagedByShadowPodValue}); err != nil {
		return ctrl.Result{}, err
	}

	// Extract pod IPs per remote cluster ID
	podIps := make(map[string][]string)
	for _, pod := range podList.Items {
		remoteClusterID, ok := pod.Labels[forge.LiqoOriginClusterIDKey]
		if !ok {
			continue
		}
		if pod.Status.PodIP == "" {
			continue
		}
		podIps[remoteClusterID] = append(podIps[remoteClusterID], pod.Status.PodIP)
	}

	// Create or update the isolation firewall configuration
	if err := createOrUpdateIsolationConfiguration(ctx, r.Client, &configList, podIps); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func isolationFirewallConfigurationEnqueuer(ctx context.Context, o client.Object) []reconcile.Request {
	return []reconcile.Request{
		{NamespacedName: types.NamespacedName{
			Name:      isolationFirewallConfigurationName,
			Namespace: isolationFirewallConfigurationNamespace,
		}},
	}
}

func (r *IsolationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.
		NewControllerManagedBy(mgr).
		For(&networkingv1beta1.FirewallConfiguration{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetName() == isolationFirewallConfigurationName && object.GetNamespace() == isolationFirewallConfigurationNamespace
		}))).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(isolationFirewallConfigurationEnqueuer)).
		Watches(&networkingv1beta1.Configuration{}, handler.EnqueueRequestsFromMapFunc(isolationFirewallConfigurationEnqueuer)).
		Complete(r)
}
