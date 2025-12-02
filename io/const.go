package main

const (
	// tableName is the name of the firewall table used by the gateway FirewallConfiguration.
	tableName = "cluster-security"

	// chainName is the name of the firewall chain used by the gateway FirewallConfiguration.
	chainName = "cluster-security-filter"

	// sourcePodIPsSetName is the name of the nftables set containing the pod IPs offloaded to the remote cluster.
	sourcePodIPsSetName = "gateway_source_pod_ips"

	// destinationPodIPsSetName is the name of the nftables set containing the pod IPs of the remote cluster.
	destinationPodIPsSetName = "gateway_destination_pod_ips"
)
