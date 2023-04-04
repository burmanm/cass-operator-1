// Copyright DataStax, Inc.
// Please see the included license file for details.

package serverconfig

import (
	"strings"
)

// This needs to be outside of the apis package or else code-gen fails
type NodeConfig map[string]interface{}

// GetModelValues will gather the cluster model values for cluster and datacenter
func GetModelValues(
	seeds []string,
	clusterName string,
	dcName string,
	graphEnabled int,
	solrEnabled int,
	sparkEnabled int,
	nativePort int,
	nativeSSLPort int,
	internodePort int,
	internodeSSLPort int,
	internodeSSLEnabled bool) NodeConfig {

	seedsString := strings.Join(seeds, ",")

	// Note: the operator does not currently support graph, solr, and spark
	modelValues := NodeConfig{
		"cluster-info": NodeConfig{
			"name":  clusterName,
			"seeds": seedsString,
		},
		"datacenter-info": NodeConfig{
			"name":          dcName,
			"graph-enabled": graphEnabled,
			"solr-enabled":  solrEnabled,
			"spark-enabled": sparkEnabled,
		},
		"cassandra-yaml": NodeConfig{},
	}

	if nativeSSLPort != 0 {
		modelValues["cassandra-yaml"].(NodeConfig)["native_transport_port_ssl"] = nativeSSLPort
	} else if nativePort != 0 {
		modelValues["cassandra-yaml"].(NodeConfig)["native_transport_port"] = nativePort
	}

	if internodeSSLPort != 0 {
		modelValues["cassandra-yaml"].(NodeConfig)["ssl_storage_port"] = internodeSSLPort
	} else if internodePort != 0 {
		modelValues["cassandra-yaml"].(NodeConfig)["storage_port"] = internodePort
	}

	if internodeSSLEnabled {
		// Keystore/Truststore passwords are not intended to be secure. changeit is the default password for all Java keystores.
		// https://github.com/cert-manager/csi-driver/pull/103#issuecomment-1188862117
		serverEncryptionOptions := NodeConfig{
			"internode_encryption": "all",
			"keystore":             "/tls/node-keystore.p12",
			"keystore_password":    "changeit",
			"truststore":           "/tls/node-keystore.p12",
			"truststore_password":  "changeit",
			"store_type":           "PKCS12",
		}
		modelValues["cassandra-yaml"].(NodeConfig)["server_encryption_options"] = serverEncryptionOptions
	}

	return modelValues
}
