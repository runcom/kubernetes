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
	"net/http"
)

type Info struct {
	StorageDriver string `json:"storage_driver"`
	StorageRoot   string `json:"storage_root"`
}

type ContainerInfo struct {
	Pid         int               `json:"pid"`
	Image       string            `json:"image"`
	CreatedTime int64             `json:"created_time"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	LogPath     string            `json:"log_path"`
	Root        string            `json:"root"`
}

type crioClient interface {
	Info() (*Info, error)
	ContainerInfo(string) (*ContainerInfo, error)
}

type crioClientImpl struct {
	client *http.Client
}

// Client ...
func Client() (crioClient, error) {
	c := &http.Client{}
	return &crioClientImpl{
		client: c,
	}, nil
}

// Info ...
func (c *crioClientImpl) Info() (*Info, error) {
	resp, err := c.client.Get("http://localhost:7373/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	info := Info{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// ContainerInfo ...
func (c *crioClientImpl) ContainerInfo(id string) (*ContainerInfo, error) {
	resp, err := c.client.Get("http://localhost:7373/containers/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	cInfo := ContainerInfo{}
	if err := json.NewDecoder(resp.Body).Decode(&cInfo); err != nil {
		return nil, err
	}
	return &cInfo, nil
}
