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

// Package kubevirt contains the cloud kubevirt specific implementations to manage machines
package core

import (
	"context"
	"fmt"
	"strconv"
	"time"

	api "github.com/gardener/machine-controller-manager-provider-kubevirt/pkg/kubevirt/apis"
	clouderrors "github.com/gardener/machine-controller-manager-provider-kubevirt/pkg/kubevirt/errors"
	"github.com/gardener/machine-controller-manager-provider-kubevirt/pkg/kubevirt/util"

	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
	utilpointer "k8s.io/utils/pointer"
	kubevirtv1 "kubevirt.io/client-go/api/v1"
	cdi "kubevirt.io/containerized-data-importer/pkg/apis/core/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ProviderName = "kubevirt"

// PluginSPIImpl is the real implementation of PluginSPI interface
// that makes the calls to the provider SDK
type PluginSPIImpl struct {
	client client.Client
}

// NewPluginSPIImpl creates a new kubevirt cloud provider based on the passed client or secret.
func NewPluginSPIImpl(client client.Client, secret *corev1.Secret) (*PluginSPIImpl, error) {
	if client != nil {
		return &PluginSPIImpl{
			client: client,
		}, nil
	}

	c, err := kubevirtClient(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}

	return &PluginSPIImpl{
		client: c,
	}, nil
}

func (p PluginSPIImpl) CreateMachine(ctx context.Context, machineName string, providerSpec *api.KubeVirtProviderSpec, secrets *corev1.Secret) (providerID string, err error) {
	requestsAndLimits, err := util.ParseResources(providerSpec.CPUs, providerSpec.Memory)
	if err != nil {
		return "", fmt.Errorf("failed to parse resources fields: %v", err)
	}

	pvcSize, err := resource.ParseQuantity(providerSpec.PVCSize)
	if err != nil {
		return "", fmt.Errorf("failed to parse value of pvcSize field: %v", err)
	}

	var (
		pvcRequest                    = corev1.ResourceList{corev1.ResourceStorage: pvcSize}
		terminationGracePeriodSeconds = int64(30)
		userdataSecretName            = fmt.Sprintf("userdata-%s-%s", machineName, strconv.Itoa(int(time.Now().Unix())))

		dnsPolicy corev1.DNSPolicy
		dnsConfig *corev1.PodDNSConfig
	)

	if providerSpec.DNSPolicy != "" {
		dnsPolicy, err = util.DNSPolicy(providerSpec.DNSPolicy)
		if err != nil {
			return "", fmt.Errorf("invalid dns policy: %v", err)
		}
	}

	if providerSpec.DNSConfig != "" {
		if err := yaml.Unmarshal([]byte(providerSpec.DNSConfig), dnsConfig); err != nil {
			return "", fmt.Errorf(`failed to unmarshal "dnsConfig" field: %v`, err)
		}
	}

	virtualMachine := &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      machineName,
			Namespace: providerSpec.Namespace,
			Labels: map[string]string{
				"kubevirt.io/vm": machineName,
			},
		},
		Spec: kubevirtv1.VirtualMachineSpec{
			Running: utilpointer.BoolPtr(true),
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubevirt.io/vm": machineName,
					},
				},
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					Domain: kubevirtv1.DomainSpec{
						Devices: kubevirtv1.Devices{
							Disks: []kubevirtv1.Disk{
								{
									Name:       "datavolumedisk",
									DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: "virtio"}},
								},
								{
									Name:       "cloudinitdisk",
									DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: "virtio"}},
								},
							},
						},
						Resources: kubevirtv1.ResourceRequirements{
							Requests: *requestsAndLimits,
							Limits:   *requestsAndLimits,
						},
					},
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
					Volumes: []kubevirtv1.Volume{
						{
							Name: "datavolumedisk",
							VolumeSource: kubevirtv1.VolumeSource{
								DataVolume: &kubevirtv1.DataVolumeSource{
									Name: machineName,
								},
							},
						},
						{
							Name: "cloudinitdisk",
							VolumeSource: kubevirtv1.VolumeSource{
								CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
									UserDataSecretRef: &corev1.LocalObjectReference{
										Name: userdataSecretName,
									},
								},
							},
						},
					},
					DNSPolicy: dnsPolicy,
					DNSConfig: dnsConfig,
				},
			},
			DataVolumeTemplates: []cdi.DataVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: machineName,
					},
					Spec: cdi.DataVolumeSpec{
						PVC: &corev1.PersistentVolumeClaimSpec{
							StorageClassName: utilpointer.StringPtr(providerSpec.StorageClassName),
							AccessModes: []corev1.PersistentVolumeAccessMode{
								"ReadWriteOnce",
							},
							Resources: corev1.ResourceRequirements{
								Requests: pvcRequest,
							},
						},
						Source: cdi.DataVolumeSource{
							HTTP: &cdi.DataVolumeSourceHTTP{
								URL: providerSpec.SourceURL,
							},
						},
					},
				},
			},
		},
	}

	if err := p.client.Create(ctx, virtualMachine); err != nil {
		return "", fmt.Errorf("failed to create vmi: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            userdataSecretName,
			Namespace:       virtualMachine.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(virtualMachine, kubevirtv1.VirtualMachineGroupVersionKind)},
		},
		Data: map[string][]byte{"userdata": []byte(secrets.Data["userData"])},
	}

	if err := p.client.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create secret for userdata: %v", err)
	}

	return p.machineProviderID(ctx, machineName, providerSpec.Namespace)
}

func (p PluginSPIImpl) DeleteMachine(ctx context.Context, machineName, providerID string, providerSpec *api.KubeVirtProviderSpec, secrets *corev1.Secret) (foundProviderID string, err error) {
	virtualMachine, err := p.getVM(ctx, machineName, providerSpec.Namespace)
	if err != nil {
		if clouderrors.IsMachineNotFoundError(err) {
			klog.V(2).Infof("skip virtualMachine evicting, virtualMachine instance %s is not found", machineName)
			return "", nil
		}
		return "", fmt.Errorf("failed to get virtualMachine: %v", err)
	}

	if err := client.IgnoreNotFound(p.client.Delete(ctx, virtualMachine)); err != nil {
		return "", fmt.Errorf("failed to delete virtualMachine %v: %v", machineName, err)
	}
	return encodeProviderID(string(virtualMachine.UID)), nil
}

func (p PluginSPIImpl) GetMachineStatus(ctx context.Context, machineName, providerID string, providerSpec *api.KubeVirtProviderSpec, secrets *corev1.Secret) (foundProviderID string, err error) {
	return p.machineProviderID(ctx, machineName, providerSpec.Namespace)
}

func (p PluginSPIImpl) ListMachines(ctx context.Context, providerSpec *api.KubeVirtProviderSpec, secrets *corev1.Secret) (providerIDList map[string]string, err error) {
	return p.listVMs(ctx, secrets)
}

func (p PluginSPIImpl) ShutDownMachine(ctx context.Context, machineName, providerID string, providerSpec *api.KubeVirtProviderSpec, secrets *corev1.Secret) (foundProviderID string, err error) {
	virtualMachine, err := p.getVM(ctx, machineName, providerSpec.Namespace)
	if err != nil {
		return "", err
	}

	virtualMachine.Spec.Running = utilpointer.BoolPtr(false)
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		return p.client.Update(ctx, virtualMachine)
	}); err != nil {
		return "", fmt.Errorf("failed to update machine running state: %v", err)
	}

	return encodeProviderID(string(virtualMachine.UID)), nil
}

func (p PluginSPIImpl) getVM(ctx context.Context, machineName, namespace string) (*kubevirtv1.VirtualMachine, error) {
	virtualMachine := &kubevirtv1.VirtualMachine{}
	if err := p.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: machineName}, virtualMachine); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, &clouderrors.MachineNotFoundError{
				Name: machineName,
			}
		}
		return nil, fmt.Errorf("failed to find kubevirt virtualMachine: %v", err)
	}

	return virtualMachine, nil
}

func (p PluginSPIImpl) listVMs(ctx context.Context, secret *corev1.Secret) (map[string]string, error) {
	virtualMachineList := &kubevirtv1.VirtualMachineList{}
	if err := p.client.List(ctx, virtualMachineList, &client.ListOptions{}); err != nil {
		return nil, fmt.Errorf("failed to list kubevirt virtual machines: %v", err)
	}

	var providerIDs = make(map[string]string, len(virtualMachineList.Items))
	for _, virtualMachine := range virtualMachineList.Items {
		providerID := encodeProviderID(string(virtualMachine.UID))
		providerIDs[providerID] = virtualMachine.Name
	}

	return providerIDs, nil
}

func (p PluginSPIImpl) machineProviderID(ctx context.Context, virtualMachineName, namespace string) (string, error) {
	virtualMachine, err := p.getVM(ctx, virtualMachineName, namespace)
	if err != nil {
		return "", fmt.Errorf("failed to get virtualMachine: %v", err)
	}

	return encodeProviderID(string(virtualMachine.UID)), nil
}
