// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

// KubeVirtProviderSpec is the spec to be used while parsing the calls.
type KubeVirtProviderSpec struct {
	// SourceURL is the HTTP URL of the source image imported by CDI.
	SourceURL string `json:"sourceURL,omitempty"`
	// StorageClassName is the name which CDI uses to in order to create claims.
	StorageClassName string `json:"storageClassName,omitempty"`
	// PVCSize is the size of the PersistentVolumeClaim that is created during the image import by CDI.
	PVCSize string `json:"pvcSize,omitempty"`
	// CPUs is the number of CPUs requested by the VM.
	CPUs string `json:"cpus,omitempty"`
	// Memory is the amount of memory requested by the VM.
	Memory string `json:"memory,omitempty"`
	// DNSConfig is the DNS configuration of the VM pod.
	// The parameters specified here will be merged with the generated DNS configuration based on DNSPolicy.
	// +optional
	DNSConfig string `json:"dnsConfig,omitempty"`
	// DNSPolicy is the DNS policy for the VM pod.
	// Defaults to "ClusterFirst" and valid values are 'ClusterFirstWithHostNet', 'ClusterFirst', 'Default' or 'None'.
	// To have DNS options set along with hostNetwork, specify DNS policy as 'ClusterFirstWithHostNet'.
	// +optional
	DNSPolicy string `json:"dnsPolicy,omitempty"`
	// SSHKeys is an optional list of SSH public keys added to the VM (may already be included in UserData)
	// +optional
	SSHKeys []string `json:"sshKeys,omitempty"`
	// Networks is an optional list of networks for the VM. If any of the networks is specified as "default"
	// the pod network won't be added, otherwise it will be added as default.
	// +optional
	Networks []NetworkSpec `json:"networks,omitempty"`
	// Tags is an optional map of tags that is added to the VM as labels.
	// +optional
	Tags map[string]string `json:"tags,omitempty"`
}

// NetworkSpec contains information about a network.
type NetworkSpec struct {
	// Name is the name (in the format <name> or <namespace>/<name>) of the network.
	Name string `json:"name"`
	// Default is whether the network is the default or not.
	// +optional
	Default bool `json:"default,omitempty"`
}
