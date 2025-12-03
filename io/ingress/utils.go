package ingress

import (
	"fmt"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	tenantnamespace "github.com/liqotech/liqo/pkg/tenantNamespace"
)

func forgeNamespaceName(clusterID string) string {
	return fmt.Sprintf("%s-%s", tenantnamespace.NamePrefix, clusterID)
}

func getConfigurationRemoteClusterID(cfg *networkingv1beta1.Configuration) (string, error) {
	// TODO: check format. We use this string for table and resource names.

	remoteClusterID, ok := cfg.Labels[string(consts.RemoteClusterID)]
	if !ok {
		return "", fmt.Errorf("configuration %q has no remote cluster ID label", cfg.Name)
	}
	return remoteClusterID, nil
}
