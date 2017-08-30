// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handler for CRI-O containers.
package crio

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/google/cadvisor/container"
	"github.com/google/cadvisor/container/common"
	containerlibcontainer "github.com/google/cadvisor/container/libcontainer"
	"github.com/google/cadvisor/fs"
	info "github.com/google/cadvisor/info/v1"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	cgroupfs "github.com/opencontainers/runc/libcontainer/cgroups/fs"
	libcontainerconfigs "github.com/opencontainers/runc/libcontainer/configs"
)

type crioContainerHandler struct {
	name               string
	id                 string
	aliases            []string
	machineInfoFactory info.MachineInfoFactory

	// Absolute path to the cgroup hierarchies of this container.
	// (e.g.: "cpu" -> "/sys/fs/cgroup/cpu/test")
	cgroupPaths map[string]string

	// Manager of this container's cgroups.
	cgroupManager cgroups.Manager

	// the docker storage driver
	storageDriver    storageDriver
	fsInfo           fs.FsInfo
	rootfsStorageDir string

	// Time at which this container was created.
	creationTime time.Time

	// Metadata associated with the container.
	labels map[string]string
	envs   map[string]string

	// TODO
	// crio version handling...

	// The container PID used to switch namespaces as required
	pid int

	// Image name used for this container.
	image string

	// The host root FS to read
	rootFs string

	// The network mode of the container
	// TODO

	// Filesystem handler.
	fsHandler common.FsHandler

	// The IP address of the container
	ipAddress string

	ignoreMetrics container.MetricSet

	// container restart count
	restartCount int
}

var _ container.ContainerHandler = &crioContainerHandler{}

func getRwLayerID(containerID, storageDir string, sd storageDriver) (string, error) {
	// TODO: return the RW layer ID
	return "", fmt.Errorf("Not yet implemented for container: %v, storageDir: %v, sd: %v", containerID, storageDir, sd)
}

// newCrioContainerHandler returns a new container.ContainerHandler
func newCrioContainerHandler(
	name string,
	machineInfoFactory info.MachineInfoFactory,
	fsInfo fs.FsInfo,
	storageDriver storageDriver,
	storageDir string,
	cgroupSubsystems *containerlibcontainer.CgroupSubsystems,
	inHostNamespace bool,
	metadataEnvs []string,
	ignoreMetrics container.MetricSet,
) (container.ContainerHandler, error) {
	// Create the cgroup paths.
	cgroupPaths := make(map[string]string, len(cgroupSubsystems.MountPoints))
	for key, val := range cgroupSubsystems.MountPoints {
		cgroupPaths[key] = path.Join(val, name)
	}

	// Generate the equivalent cgroup manager for this container.
	cgroupManager := &cgroupfs.Manager{
		Cgroups: &libcontainerconfigs.Cgroup{
			Name: name,
		},
		Paths: cgroupPaths,
	}

	rootFs := "/"
	if !inHostNamespace {
		rootFs = "/rootfs"
		storageDir = path.Join(rootFs, storageDir)
	}

	id := ContainerNameToCrioId(name)

	// TODO track where container log files are stored
	rwLayerID, err := getRwLayerID(id, storageDir, storageDriver)
	if err != nil {
		// TODO: fix this and make
		fmt.Println("Ignoring error in crio to get rw layer id: %v", err)
	}

	// Determine the rootfs storage dir
	var (
		rootfsStorageDir string
	)
	switch storageDriver {
	case overlayStorageDriver, overlay2StorageDriver:
		rootfsStorageDir = path.Join(storageDir, string(storageDriver), rwLayerID)
	}

	// TODO: extract object mother method
	handler := &crioContainerHandler{
		id:                 id,
		name:               name,
		machineInfoFactory: machineInfoFactory,
		cgroupPaths:        cgroupPaths,
		cgroupManager:      cgroupManager,
		storageDriver:      storageDriver,
		fsInfo:             fsInfo,
		rootFs:             rootFs,
		rootfsStorageDir:   rootfsStorageDir,
		envs:               make(map[string]string),
		ignoreMetrics:      ignoreMetrics,
	}

	crioRun := "/run/containers/storage/%s-containers/%s"
	pidfile := filepath.Join(fmt.Sprintf(crioRun, storageDriver, id), "userdata", "pidfile")
	config := filepath.Join(fmt.Sprintf(crioRun, storageDriver, id), "userdata", "config.json")
	cBytes, err := ioutil.ReadFile(config)
	if err != nil {
		glog.Infof("CRIO HANDLER ERROR READING CONFIG: %v", err)
		return nil, err
	}
	var m struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	}
	if err = json.Unmarshal(cBytes, &m); err != nil {
		glog.Infof("CRIO HANDLER ERROR READING Annotations: %v", err)
		return nil, err
	}

	created, err := time.Parse(time.RFC3339Nano, m.Annotations["io.kubernetes.cri-o.Created"])
	if err != nil {
		glog.Infof("CRIO HANDLER ERROR READING CREATE TIMESTAMP: %v", err)
		return nil, err
	}
	handler.creationTime = created

	pidfileBytes, err := ioutil.ReadFile(pidfile)
	if err != nil {
		glog.Infof("CRIO HANDLER ERROR READING PIDFILE: %v", err)
		return nil, err
	}
	pid, err := strconv.Atoi(string(pidfileBytes))
	if err != nil {
		glog.Infof("CRIO HANDLER ERROR READING PID: %v", err)
		return nil, err
	}
	handler.pid = pid

	labels := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["io.kubernetes.cri-o.Labels"]), &labels); err != nil {
		glog.Infof("CRIO HANDLER ERROR READING LABELS: %v", err)
		return nil, err
	}
	annotations := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["io.kubernetes.cri-o.Annotations"]), &annotations); err != nil {
		glog.Infof("CRIO HANDLER ERROR READING ANNOTATIONS: %v", err)
		return nil, err
	}

	// we don't need "aliases" in CRI-O
	handler.aliases = []string{}
	handler.labels = map[string]string{}
	for k, v := range labels {
		handler.labels[k] = v
	}
	handler.image = m.Annotations["io.kubernetes.cri-o.ImageName"]
	// TODO: we wanted to know cntr.HostConfig.NetworkMode?
	// TODO: we wantd to know graph driver DeviceId (dont think this is needed now)

	restartCount, err := strconv.Atoi(annotations["io.kubernetes.container.restartCount"])
	if err != nil {
		glog.Infof("CRIO HANDLER ERROR READING RESTART COUNT: %v", err)
		return nil, err
	}
	handler.restartCount = restartCount

	// TODO: we want to know the ip address of the container
	handler.ipAddress = m.Annotations["io.kubernetes.cri-o.IP"]
	// we optionally collect disk usage metrics
	if !ignoreMetrics.Has(container.DiskUsageMetrics) {
		// TODO: add a handler.fsHandler
	}
	// TODO for env vars we wanted to show from container.Config.Env from whitelist
	for _, exposedEnv := range metadataEnvs {
		glog.Infof("TODO env whitelist: %v", exposedEnv)
	}

	glog.Infof("CRIO HANDLER: %v", handler)
	return handler, nil
}

func (self *crioContainerHandler) Start() {
	if self.fsHandler != nil {
		self.fsHandler.Start()
	}
}

func (self *crioContainerHandler) Cleanup() {
	if self.fsHandler != nil {
		self.fsHandler.Stop()
	}
}

func (self *crioContainerHandler) ContainerReference() (info.ContainerReference, error) {
	return info.ContainerReference{
		Id:        self.id,
		Name:      self.name,
		Aliases:   self.aliases,
		Namespace: CrioNamespace,
		Labels:    self.labels,
	}, nil
}

func (self *crioContainerHandler) needNet() bool {
	if !self.ignoreMetrics.Has(container.NetworkUsageMetrics) {
		// TODO this should be more intelligent
		return false
		// return !self.networkMode.IsContainer()
	}
	return false
}

func (self *crioContainerHandler) GetSpec() (info.ContainerSpec, error) {
	hasFilesystem := !self.ignoreMetrics.Has(container.DiskUsageMetrics)
	spec, err := common.GetSpec(self.cgroupPaths, self.machineInfoFactory, self.needNet(), hasFilesystem)

	spec.Labels = self.labels
	// Only adds restartcount label if it's greater than 0
	if self.restartCount > 0 {
		spec.Labels["restartcount"] = strconv.Itoa(self.restartCount)
	}
	spec.Envs = self.envs
	spec.Image = self.image

	return spec, err
}

func (self *crioContainerHandler) getFsStats(stats *info.ContainerStats) error {
	mi, err := self.machineInfoFactory.GetMachineInfo()
	if err != nil {
		return err
	}

	if !self.ignoreMetrics.Has(container.DiskIOMetrics) {
		common.AssignDeviceNamesToDiskStats((*common.MachineInfoNamer)(mi), &stats.DiskIo)
	}

	if self.ignoreMetrics.Has(container.DiskUsageMetrics) {
		return nil
	}
	var device string
	switch self.storageDriver {
	case overlay2StorageDriver:
		deviceInfo, err := self.fsInfo.GetDirFsDevice(self.rootfsStorageDir)
		if err != nil {
			return fmt.Errorf("unable to determine device info for dir: %v: %v", self.rootfsStorageDir, err)
		}
		device = deviceInfo.Device
	default:
		return nil
	}

	var (
		limit  uint64
		fsType string
	)

	// crio does not impose any filesystem limits for containers. So use capacity as limit.
	for _, fs := range mi.Filesystems {
		if fs.Device == device {
			limit = fs.Capacity
			fsType = fs.Type
			break
		}
	}

	fsStat := info.FsStats{Device: device, Type: fsType, Limit: limit}
	usage := self.fsHandler.Usage()
	fsStat.BaseUsage = usage.BaseUsageBytes
	fsStat.Usage = usage.TotalUsageBytes
	fsStat.Inodes = usage.InodeUsage

	stats.Filesystem = append(stats.Filesystem, fsStat)

	return nil
}

func (self *crioContainerHandler) GetStats() (*info.ContainerStats, error) {
	stats, err := containerlibcontainer.GetStats(self.cgroupManager, self.rootFs, self.pid, self.ignoreMetrics)
	if err != nil {
		return stats, err
	}
	// Clean up stats for containers that don't have their own network - this
	// includes containers running in Kubernetes pods that use the network of the
	// infrastructure container. This stops metrics being reported multiple times
	// for each container in a pod.
	if !self.needNet() {
		stats.Network = info.NetworkStats{}
	}

	// Get filesystem stats.
	err = self.getFsStats(stats)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

func (self *crioContainerHandler) ListContainers(listType container.ListType) ([]info.ContainerReference, error) {
	// No-op for Docker driver.
	return []info.ContainerReference{}, nil
}

func (self *crioContainerHandler) GetCgroupPath(resource string) (string, error) {
	path, ok := self.cgroupPaths[resource]
	if !ok {
		return "", fmt.Errorf("could not find path for resource %q for container %q\n", resource, self.name)
	}
	return path, nil
}

func (self *crioContainerHandler) GetContainerLabels() map[string]string {
	return self.labels
}

func (self *crioContainerHandler) GetContainerIPAddress() string {
	return self.ipAddress
}

func (self *crioContainerHandler) ListProcesses(listType container.ListType) ([]int, error) {
	return containerlibcontainer.GetProcesses(self.cgroupManager)
}

func (self *crioContainerHandler) Exists() bool {
	return common.CgroupExists(self.cgroupPaths)
}

func (self *crioContainerHandler) Type() container.ContainerType {
	return container.ContainerTypeCrio
}
