package main

const (
	// tableName is the name of the firewall table used by the gateway FirewallConfiguration.
	tableName = "cluster-security"

	// chainName is the name of the firewall chain used by the gateway FirewallConfiguration.
	chainName = "cluster-security-filter"

	// podIPsSetName is the name of the nftables set containing the pod IPs of the remote cluster.
	podIPsSetName = "gateway_pod_ips"
)
