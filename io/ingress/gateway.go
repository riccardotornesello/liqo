package ingress

import (
	"context"
	"fmt"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	networkingv1beta1firewall "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
	"github.com/liqotech/liqo/pkg/firewall"
	"github.com/liqotech/liqo/pkg/gateway"
	"github.com/liqotech/liqo/pkg/gateway/tunnel"
	"github.com/liqotech/liqo/pkg/utils/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func forgeGatewayResourceName(clusterID string) string {
	return fmt.Sprintf("%s-security-gateway", clusterID)
}

func forgeGatewayLabels(clusterID string) map[string]string {
	// TODO: liqo managed?
	// TODO: category security?

	return map[string]string{
		firewall.FirewallCategoryTargetKey: gateway.FirewallCategoryGwTargetValue,
		firewall.FirewallUniqueTargetKey:   string(clusterID),
	}
}

func forgeGatewaySpec(cfg *networkingv1beta1.Configuration, sourcePodIps, destinationPodIps []string) (*networkingv1beta1.FirewallConfigurationSpec, error) {
	filterRules := []networkingv1beta1firewall.FilterRule{}
	chainPolicy := networkingv1beta1firewall.ChainPolicyAccept

	// Generate the set containing the pod IPs of the remote cluster
	destinationSetElements := make([]networkingv1beta1firewall.SetElement, 0, len(destinationPodIps))
	for _, ip := range destinationPodIps {
		destinationSetElements = append(destinationSetElements, networkingv1beta1firewall.SetElement{
			Key: ip,
		})
	}

	sourceSetElements := make([]networkingv1beta1firewall.SetElement, 0, len(sourcePodIps))
	for _, ip := range sourcePodIps {
		sourceSetElements = append(sourceSetElements, networkingv1beta1firewall.SetElement{
			Key: ip,
		})
	}

	sets := []networkingv1beta1firewall.Set{{
		Name:     destinationPodIPsSetName,
		KeyType:  networkingv1beta1firewall.SetDataTypeIPAddr,
		Elements: destinationSetElements,
	}, {
		Name:     sourcePodIPsSetName,
		KeyType:  networkingv1beta1firewall.SetDataTypeIPAddr,
		Elements: sourceSetElements,
	}}

	// Configure ingress rules based on the configuration spec
	if cfg.Spec.Security != nil && cfg.Spec.Security.Ingress != nil && *cfg.Spec.Security.Ingress != networkingv1beta1.IngressPolicyAllow {
		chainPolicy = networkingv1beta1firewall.ChainPolicyDrop

		filterRules = []networkingv1beta1firewall.FilterRule{
			// Always accept traffic not coming from the tunnel interface or going to the main interface.
			{
				Action: networkingv1beta1firewall.ActionAccept,
				Match: []networkingv1beta1firewall.Match{{
					Dev: &networkingv1beta1firewall.MatchDev{
						Position: networkingv1beta1firewall.MatchDevPositionIn,
						Value:    tunnel.TunnelInterfaceName,
					},
					Op: networkingv1beta1firewall.MatchOperationNeq,
				}},
			},
			{
				Action: networkingv1beta1firewall.ActionAccept,
				Match: []networkingv1beta1firewall.Match{{
					Dev: &networkingv1beta1firewall.MatchDev{
						Position: networkingv1beta1firewall.MatchDevPositionOut,
						Value:    "eth0", // TODO: variable?
					},
					Op: networkingv1beta1firewall.MatchOperationEq,
				}},
			},
			// Always allow established and related connections.
			{
				Action: networkingv1beta1firewall.ActionAccept,
				Match: []networkingv1beta1firewall.Match{{
					CtState: &networkingv1beta1firewall.MatchCtState{
						Value: []networkingv1beta1firewall.CtStateValue{"established", "related"},
					},
					Op: networkingv1beta1firewall.MatchOperationEq,
				}},
			},
		}

		if *cfg.Spec.Security.Ingress != networkingv1beta1.IngressPolicyDeny {
			// Accept only traffic destined to the cluster CIDR coming from the tunnel interface.
			filterRules = append(filterRules,
				networkingv1beta1firewall.FilterRule{
					Action: networkingv1beta1firewall.ActionAccept,
					Match: []networkingv1beta1firewall.Match{
						{
							IP: &networkingv1beta1firewall.MatchIP{
								Position: networkingv1beta1firewall.MatchPositionDst,
								Value:    fmt.Sprintf("@%s", destinationPodIPsSetName),
							},
							Op: networkingv1beta1firewall.MatchOperationEq,
						},
					},
				},
				networkingv1beta1firewall.FilterRule{
					Action: networkingv1beta1firewall.ActionAccept,
					Match: []networkingv1beta1firewall.Match{
						{
							IP: &networkingv1beta1firewall.MatchIP{
								Position: networkingv1beta1firewall.MatchPositionSrc,
								Value:    fmt.Sprintf("@%s", sourcePodIPsSetName),
							},
							Op: networkingv1beta1firewall.MatchOperationEq,
						},
					},
				},
			)
		}
	}

	return &networkingv1beta1.FirewallConfigurationSpec{
		Table: networkingv1beta1firewall.Table{
			Name:   ptr.To(tableName),
			Family: ptr.To(networkingv1beta1firewall.TableFamilyIPv4),
			Sets:   sets,
			Chains: []networkingv1beta1firewall.Chain{{
				Name:     ptr.To(chainName),
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

func createOrUpdateGatewayConfiguration(ctx context.Context, cl client.Client, cfg *networkingv1beta1.Configuration, sourcePodIps, destinationPodIps []string, scheme *runtime.Scheme) error {
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
		mutateGatewayConfiguration(fwcfg, cfg, sourcePodIps, destinationPodIps, scheme),
	); err != nil {
		return err
	}

	klog.Infof("Firewall configuration %q for %q created", fwcfg.Name, remoteClusterID)

	return nil
}

func mutateGatewayConfiguration(fwcfg *networkingv1beta1.FirewallConfiguration, cfg *networkingv1beta1.Configuration, sourcePodIps, destinationPodIps []string, scheme *runtime.Scheme) func() error {
	return func() error {
		if cfg.Labels == nil {
			return fmt.Errorf("configuration %q has no labels", cfg.Name)
		}

		remoteClusterID, err := getConfigurationRemoteClusterID(cfg)
		if err != nil {
			return err
		}

		fwcfg.SetLabels(forgeGatewayLabels(remoteClusterID))

		spec, err := forgeGatewaySpec(cfg, sourcePodIps, destinationPodIps)
		if err != nil {
			return err
		}
		fwcfg.Spec = *spec

		return controllerutil.SetOwnerReference(cfg, fwcfg, scheme)
	}
}
