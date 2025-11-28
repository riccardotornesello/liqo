package main

import (
	"context"
	"flag"
	"fmt"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	firewallapi "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
	"github.com/liqotech/liqo/pkg/firewall"
	tenantnamespace "github.com/liqotech/liqo/pkg/tenantNamespace"
	"github.com/liqotech/liqo/pkg/utils"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme = runtime.NewScheme()
)

const (
	GatewayResourceNamePrefix = "security-gateway"
	GatewayTableName          = "cluster-security"
)

type TestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func generateNamespaceName(clusterID liqov1beta1.ClusterID) string {
	return fmt.Sprintf("%s-%s", tenantnamespace.NamePrefix, clusterID)
}

func generateGatewayResourceName(clusterID liqov1beta1.ClusterID) string {
	return fmt.Sprintf("%s-%s", GatewayResourceNamePrefix, clusterID)
}

func generateGatewayLabels(clusterID liqov1beta1.ClusterID) map[string]string {
	// TODO: fare ordine fra le label del gateway
	return map[string]string{
		firewall.FirewallCategoryTargetKey:    "gateway",
		firewall.FirewallSubCategoryTargetKey: "security",
		firewall.FirewallUniqueTargetKey:      string(clusterID),
	}
}

func newGatewayFirewallConfiguration(clusterID liqov1beta1.ClusterID) *networkingv1beta1.FirewallConfiguration {
	return &networkingv1beta1.FirewallConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateGatewayResourceName(clusterID),
			Namespace: generateNamespaceName(clusterID),
			Labels:    generateGatewayLabels(clusterID),
		},
		Spec: networkingv1beta1.FirewallConfigurationSpec{
			Table: firewallapi.Table{
				Name:   ptr.To(GatewayTableName),
				Family: ptr.To(firewallapi.TableFamilyIPv4),
				Chains: []firewallapi.Chain{},
			},
		},
	}
}

func getGatewayFirewallConfigForCluster(ctx context.Context, cl client.Client, clusterID liqov1beta1.ClusterID) (*networkingv1beta1.FirewallConfiguration, error) {
	lSelector := labels.SelectorFromSet(generateGatewayLabels(clusterID))

	firewallConfigurationList := networkingv1beta1.FirewallConfigurationList{}
	if err := cl.List(ctx, &firewallConfigurationList, &client.ListOptions{
		LabelSelector: lSelector,
	}); err != nil {
		return nil, err
	}

	switch len(firewallConfigurationList.Items) {
	case 0:
		return nil, errors.NewNotFound(networkingv1beta1.FirewallConfigurationGroupResource, fmt.Sprintf("Gateway FirewallConfiguration for clusterID %s", clusterID))
	case 1:
		return &firewallConfigurationList.Items[0], nil
	default:
		return nil, fmt.Errorf("multiple Gateway FirewallConfiguration resources found for clusterID %s", clusterID)
	}
}

func (r *TestReconciler) foreignClusterToFirewallConfigEnqueuer(ctx context.Context, obj client.Object) []ctrl.Request {
	// TODO: handle fabric

	clusterID, ok := utils.GetClusterIDFromLabels(obj.GetLabels())
	if !ok {
		klog.Infof("resource %q has no clusterID label", klog.KObj(obj))
		return nil
	}

	gwfc, err := getGatewayFirewallConfigForCluster(ctx, r.Client, clusterID)
	switch {
	case errors.IsNotFound(err):
		// Create FirewallConfiguration
		klog.Infof("creating gateway FirewallConfiguration %q", clusterID)
		gwfc = newGatewayFirewallConfiguration(clusterID)
		if err := r.Create(ctx, gwfc); err != nil {
			klog.Errorf("an error occurred while creating gateway FirewallConfiguration %q: %s", clusterID, err)
			return nil
		}
		klog.Infof("Created gateway FirewallConfiguration %q", clusterID)
		return nil
	case err != nil:
		klog.Errorf("an error occurred while getting gateway FirewallConfiguration %q: %s", clusterID, err)
		return nil
	default:
		klog.Infof("enqueuing gateway FirewallConfiguration %q", clusterID)
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: gwfc.Name, Namespace: gwfc.Namespace}}}
	}
}

func (r *TestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Reconciling FirewallConfiguration %s/%s", req.Namespace, req.Name)
	return ctrl.Result{}, nil
}

func (r *TestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.
		NewControllerManagedBy(mgr).
		Named("TEST").
		For(&networkingv1beta1.FirewallConfiguration{}).
		Watches(
			&liqov1beta1.ForeignCluster{},
			handler.EnqueueRequestsFromMapFunc(r.foreignClusterToFirewallConfigEnqueuer),
		).
		Complete(r)
}

func init() {
	utilruntime.Must(networkingv1beta1.AddToScheme(scheme))
	utilruntime.Must(liqov1beta1.AddToScheme(scheme))
}

func main() {
	flag.Parse()

	//----------- LOGGING
	log.SetLogger(klog.NewKlogr())

	//----------- MANAGER
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: ":8080",
		},
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		panic(err)
	}

	//---------- RECONCILER
	r := &TestReconciler{
		Scheme: mgr.GetScheme(),
		Client: mgr.GetClient(),
	}

	if err = r.SetupWithManager(mgr); err != nil {
		panic(err)
	}

	//---------- START
	klog.Info("starting manager as controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		panic(err)
	}
}
