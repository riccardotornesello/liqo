package main

const (
	// gatewayTableName is the name of the firewall table used by the gateway FirewallConfiguration.
	gatewayTableName = "cluster-security"

	// gatewayChainName is the name of the firewall chain used by the gateway FirewallConfiguration.
	gatewayChainName = "cluster-security-filter"

	// firewallCategoryTargetValueGw is the value used by the securityconfiguration controller to reconcile only resources related to a gateway.
	firewallCategoryTargetValueGw = "gateway"

	// firewallSubCategoryTargetValueSecurity is the value used by the securityconfiguration controller to reconcile only resources related to the IP mapping.
	firewallSubCategoryTargetValueSecurity = "security"
)
