package isolation

const (
	// isolationTableName is the name of the firewall table used by the isolation FirewallConfiguration.
	isolationTableName = "cluster-isolation"

	// isolationChainName is the name of the firewall chain used by the isolation FirewallConfiguration.
	isolationChainName = "cluster-isolation-filter"

	// isolationFirewallConfigurationName is the name of the isolation FirewallConfiguration.
	isolationFirewallConfigurationName = "security-isolation"

	// isolationFirewallConfigurationNamespace is the namespace of the isolation FirewallConfiguration.
	isolationFirewallConfigurationNamespace = "liqo"
)
