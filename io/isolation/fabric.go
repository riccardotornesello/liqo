package isolation

import (
	"context"
	"fmt"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	networkingv1beta1firewall "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
	"github.com/liqotech/liqo/pkg/fabric"
	"github.com/liqotech/liqo/pkg/firewall"
	"github.com/liqotech/liqo/pkg/utils/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func forgeIsolationLabels() map[string]string {
	// TODO: liqo managed?
	// TODO: category security?

	return map[string]string{
		firewall.FirewallCategoryTargetKey:    fabric.FirewallCategoryTargetValue,
		firewall.FirewallSubCategoryTargetKey: fabric.FirewallSubCategoryTargetAllNodesValue,
	}
}

func forgeIsolationSpec(configList *networkingv1beta1.ConfigurationList, podIps map[string][]string) (*networkingv1beta1.FirewallConfigurationSpec, error) {
	filterRules := []networkingv1beta1firewall.FilterRule{}
	chainPolicy := networkingv1beta1firewall.ChainPolicyAccept

	// TODO: generate filter rules

	// Generate the set containing the pod IPs of the remote cluster
	sets := make([]networkingv1beta1firewall.Set, 0, len(configList.Items))
	for _, cfg := range configList.Items {
		remoteClusterID, err := getConfigurationRemoteClusterID(&cfg)
		if err != nil {
			return nil, err
		}

		setElements := make([]networkingv1beta1firewall.SetElement, 0)

		clusterPodIps, ok := podIps[remoteClusterID]
		if ok {
			setElements = make([]networkingv1beta1firewall.SetElement, 0, len(clusterPodIps))
			for _, ip := range clusterPodIps {
				setElements = append(setElements, networkingv1beta1firewall.SetElement{
					Key: ip,
				})
			}
		}

		sets = append(sets, networkingv1beta1firewall.Set{
			Name:     fmt.Sprintf("pod_ips_%s", remoteClusterID),
			KeyType:  networkingv1beta1firewall.SetDataTypeIPAddr,
			Elements: setElements,
		})
	}

	return &networkingv1beta1.FirewallConfigurationSpec{
		Table: networkingv1beta1firewall.Table{
			Name:   ptr.To(isolationTableName),
			Family: ptr.To(networkingv1beta1firewall.TableFamilyIPv4),
			Sets:   sets,
			Chains: []networkingv1beta1firewall.Chain{{
				Name:     ptr.To(isolationChainName),
				Hook:     ptr.To(networkingv1beta1firewall.ChainHookPostrouting),
				Policy:   ptr.To(chainPolicy),
				Priority: ptr.To[networkingv1beta1firewall.ChainPriority](200),
				Type:     ptr.To(networkingv1beta1firewall.ChainTypeFilter),
				Rules: networkingv1beta1firewall.RulesSet{
					FilterRules: filterRules,
				},
			}},
		},
	}, nil
}

func createOrUpdateIsolationConfiguration(ctx context.Context, cl client.Client, configList *networkingv1beta1.ConfigurationList, podIps map[string][]string) error {
	fwcfg := &networkingv1beta1.FirewallConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      isolationFirewallConfigurationName,
			Namespace: isolationFirewallConfigurationNamespace,
		},
	}

	if _, err := resource.CreateOrUpdate(
		ctx, cl, fwcfg,
		mutateIsolationConfiguration(fwcfg, configList, podIps),
	); err != nil {
		return err
	}

	return nil
}

func mutateIsolationConfiguration(fwcfg *networkingv1beta1.FirewallConfiguration, configList *networkingv1beta1.ConfigurationList, podIps map[string][]string) func() error {
	return func() error {
		fwcfg.SetLabels(forgeIsolationLabels())

		spec, err := forgeIsolationSpec(configList, podIps)
		if err != nil {
			return err
		}
		fwcfg.Spec = *spec

		// TODO: SetControllerReference

		return nil
	}
}
