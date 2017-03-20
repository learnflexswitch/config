//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	modelObjs "models/objects"
	"os"
	"strings"
	"time"
)

type Repo struct {
	Name   string `json:Name`
	Sha1   string `json:Sha1`
	Branch string `json:Branch`
	Time   string `json:Time`
}

type Version struct {
	Major       string `json:"major"`
	Minor       string `json:"minor"`
	Patch       string `json:"patch"`
	Build       string `json:"build"`
	Changeindex string `json:"changeindex"`
}

type SwVersion struct {
	SwVersion string
	Repos     []Repo
}

type SwitchCfgJson struct {
	SwitchMac   string `json:"SwitchMac"`
	Hostname    string `json:"HostName"`
	SwVersion   string `json:"Version"`
	MgmtIp      string `json:"MgmtIp"`
	Description string `json:"Description"`
	Vrf         string `json:"Vrf"`
}

func (mgr *ConfigMgr) ReadSystemSwVersion() error {
	var version Version
	paramsDir := mgr.paramsDir
	infoDir := strings.TrimSuffix(paramsDir, "params/")
	pkgInfoFile := infoDir + "pkgInfo.json"
	bytes, err := ioutil.ReadFile(pkgInfoFile)
	if err != nil {
		mgr.logger.Err("Error in reading configuration file " + pkgInfoFile)
		return err
	}

	err = json.Unmarshal(bytes, &version)
	if err != nil {
		mgr.logger.Err("Error in Unmarshalling pkgInfo Json")
		return err
	}
	mgr.swVersion.SwVersion = version.Major + "." + version.Minor + "." + version.Patch + "." + version.Build + "." + version.Changeindex

	buildInfoFile := infoDir + "buildInfo.json"
	bytes, err = ioutil.ReadFile(buildInfoFile)
	if err != nil {
		mgr.logger.Err("Error in reading configuration file", buildInfoFile)
		return err
	}

	err = json.Unmarshal(bytes, &mgr.swVersion.Repos)
	if err != nil {
		mgr.logger.Err("Error in Unmarshalling buildInfo Json")
		return err
	}
	return nil
}

func (mgr *ConfigMgr) ConstructSystemParam(clientName string) error {
	if clientName != "sysd" {
		return nil
	}
	paramsDir := mgr.paramsDir
	sysInfo := &modelObjs.SystemParam{}
	// check if object exists in db or not
	if objHdl, ok := modelObjs.ConfigObjectMap["systemparam"]; ok {
		var body []byte // @dummy body for default objects
		obj, _ := objHdl.UnmarshalObject(body)
		data := obj.(modelObjs.SystemParam)
		_, err := mgr.dbHdl.GetObjectFromDb(data, data.GetKey())
		if err == nil {
			return nil
		}
	}

	cfgFileData, err := ioutil.ReadFile(paramsDir + "systemProfile.json")
	if err != nil {
		mgr.logger.Err("Error reading file, err:", err)
		return err
	}
	// Get this info from systemProfile
	var cfg SwitchCfgJson
	err = json.Unmarshal(cfgFileData, &cfg)
	if err != nil {
		mgr.logger.Err("Error Unmarshalling cfg json data, err:", err)
		return err
	}

	versionFileData, err := ioutil.ReadFile(strings.TrimSuffix(paramsDir, "params/") + "pkgInfo.json")
	if err != nil {
		mgr.logger.Err("Error in reading sw version file", err)
		return err
	}
	var version Version
	err = json.Unmarshal(versionFileData, &version)
	if err != nil {
		mgr.logger.Err("Error in Unmarshalling pkgInfo Json")
		return err
	}
	sysInfo.SwVersion = version.Major + "." + version.Minor + "." + version.Patch + "." + version.Build
	sysInfo.SwitchMac = cfg.SwitchMac
	sysInfo.MgmtIp = cfg.MgmtIp
	sysInfo.Description = cfg.Description
	sysInfo.Hostname = cfg.Hostname
	sysInfo.Vrf = cfg.Vrf
	sysBody, err := json.Marshal(sysInfo)
	if err != nil {
		mgr.logger.Err("Error marshalling system info, err:", err)
		return err
	}
	if objHdl, ok := modelObjs.ConfigObjectMap["systemparam"]; ok {
		sysObj, _ := objHdl.UnmarshalObject(sysBody)
		client, exist := mgr.clientMgr.Clients[clientName]
		if exist {
			err, success := client.CreateObject(sysObj, mgr.dbHdl.DBUtil)
			if err == nil && success == true {
				mgr.storeUUID(sysObj.GetKey())
			} else {
				mgr.logger.Err("Failed to create system info: ", err)
			}
		}
	}

	return err
}

func (mgr *ConfigMgr) ConfigureComponentLoggingLevel(compName string) {
	var data modelObjs.ComponentLogging
	var modName string
	var err error

	// Client name for confd is configured as "local" in json file.
	if compName == "local" {
		modName = "confd"
	} else {
		modName = compName
	}

	mgr.logger.Info("Check component logging config in DB for ", modName)
	if objHdl, ok := modelObjs.ConfigObjectMap["componentlogging"]; ok {
		var body []byte // @dummy body for default objects
		obj, _ := objHdl.UnmarshalObject(body)
		data = obj.(modelObjs.ComponentLogging)
		data.Module = modName
		_, err = mgr.dbHdl.GetObjectFromDb(data, data.GetKey())
	}
	if err != nil {
		// ComponentLogging is not created in DB. Create with default logging level and store in DB
		err = mgr.dbHdl.StoreObjectInDb(data)
		if err == nil {
			mgr.storeUUID(data.GetKey())
		}
	}
}

func GetSystemStatus() modelObjs.SystemStatusState {
	systemStatus := modelObjs.SystemStatusState{}
	systemStatus.Name, _ = os.Hostname()
	systemStatus.Ready = gConfigMgr.clientMgr.IsReady()
	if systemStatus.Ready == false {
		reason := "Not connected to"
		unconnectedClients := gConfigMgr.clientMgr.GetUnconnectedClients()
		for idx := 0; idx < len(unconnectedClients); idx++ {
			reason = reason + " " + unconnectedClients[idx]
		}
		systemStatus.Reason = reason
	} else {
		systemStatus.Reason = "None"
	}
	systemStatus.UpTime = time.Since(gConfigMgr.bringUpTime).String()
	systemStatus.NumCreateCalls =
		fmt.Sprintf("Total %d Success %d", gConfigMgr.ApiMgr.ApiCallStats.NumCreateCalls, gConfigMgr.ApiMgr.ApiCallStats.NumCreateCallsSuccess)
	systemStatus.NumDeleteCalls =
		fmt.Sprintf("Total %d Success %d", gConfigMgr.ApiMgr.ApiCallStats.NumDeleteCalls, gConfigMgr.ApiMgr.ApiCallStats.NumDeleteCallsSuccess)
	systemStatus.NumUpdateCalls =
		fmt.Sprintf("Total %d Success %d", gConfigMgr.ApiMgr.ApiCallStats.NumUpdateCalls, gConfigMgr.ApiMgr.ApiCallStats.NumUpdateCallsSuccess)
	systemStatus.NumGetCalls =
		fmt.Sprintf("Total %d Success %d", gConfigMgr.ApiMgr.ApiCallStats.NumGetCalls, gConfigMgr.ApiMgr.ApiCallStats.NumGetCallsSuccess)
	systemStatus.NumActionCalls =
		fmt.Sprintf("Total %d Success %d", gConfigMgr.ApiMgr.ApiCallStats.NumActionCalls, gConfigMgr.ApiMgr.ApiCallStats.NumActionCallsSuccess)

	// Read DaemonStates from db
	var daemonState modelObjs.DaemonState
	daemonStates, _ := gConfigMgr.dbHdl.GetAllObjFromDb(daemonState)
	systemStatus.FlexDaemons = make([]modelObjs.DaemonState, len(daemonStates))
	for idx, daemonState := range daemonStates {
		systemStatus.FlexDaemons[idx] = daemonState.(modelObjs.DaemonState)
	}
	return systemStatus
}

func GetSystemSwVersion() modelObjs.SystemSwVersionState {
	systemSwVersion := modelObjs.SystemSwVersionState{}
	err := gConfigMgr.ReadSystemSwVersion()
	if err != nil {
		gConfigMgr.logger.Info("Failed to read sw version")
	}
	systemSwVersion.FlexswitchVersion = gConfigMgr.swVersion.SwVersion
	numRepos := len(gConfigMgr.swVersion.Repos)
	systemSwVersion.Repos = make([]modelObjs.RepoInfo, numRepos)
	for i := 0; i < numRepos; i++ {
		systemSwVersion.Repos[i].Name = gConfigMgr.swVersion.Repos[i].Name
		systemSwVersion.Repos[i].Sha1 = gConfigMgr.swVersion.Repos[i].Sha1
		systemSwVersion.Repos[i].Branch = gConfigMgr.swVersion.Repos[i].Branch
		systemSwVersion.Repos[i].Time = gConfigMgr.swVersion.Repos[i].Time
	}
	return systemSwVersion
}
