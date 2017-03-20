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

package clients

import (
	"encoding/json"
	"io/ioutil"
	"models/actions"
	"models/objects"
	"sort"
	"strings"
	"sync"
	"utils/dbutils"
	"utils/ipcutils"
)

type LocalClient struct {
	ipcutils.IPCClientBase
}

func (clnt *LocalClient) Initialize(name string, address string) {
	clnt.Name = name
	clnt.Address = address
	clnt.ApiHandlerMutex = sync.RWMutex{}
	return
}

func (clnt *LocalClient) ConnectToServer() bool {
	return true
}

func (clnt *LocalClient) DisconnectFromServer() bool {
	return true
}

func (clnt *LocalClient) IsConnectedToServer() bool {
	return true
}

func (clnt *LocalClient) DisableServer() bool {
	return true
}

func (clnt *LocalClient) IsServerEnabled() bool {
	return true
}

func (clnt *LocalClient) GetServerName() string {
	return "local"
}

func (clnt *LocalClient) LockApiHandler() {
	clnt.ApiHandlerMutex.Lock()
}

func (clnt *LocalClient) UnlockApiHandler() {
	clnt.ApiHandlerMutex.Unlock()
}

func (clnt *LocalClient) CreateObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, bool) {
	var err error
	var ok bool = true
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	default:
		break
	}
	return err, ok
}

func (clnt *LocalClient) DeleteObject(obj objects.ConfigObj, objKey string, dbHdl *dbutils.DBUtil) (error, bool) {
	var err error
	var ok bool = true
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	default:
		break
	}
	return err, ok
}

func (clnt *LocalClient) GetBulkObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil, currMarker int64, count int64) (err error,
	objCount int64,
	nextMarker int64,
	more bool,
	objs []objects.ConfigObj) {
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	case objects.ConfigLogState:
		objCount, nextMarker, more, objs = getApiHistory(dbHdl)
	default:
		break
	}
	return nil, objCount, nextMarker, more, objs
}

func (clnt *LocalClient) UpdateObject(dbObj objects.ConfigObj, obj objects.ConfigObj, attrSet []bool, op []objects.PatchOpInfo, objKey string, dbHdl *dbutils.DBUtil) (error, bool) {
	var err error
	var ok bool
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	default:
		break
	}
	return err, ok
}

func (clnt *LocalClient) GetObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, objects.ConfigObj) {
	var retObj objects.ConfigObj
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	case objects.SystemStatusState:
		retObj = gClientMgr.systemStatusCB()
	case objects.SystemSwVersionState:
		retObj = gClientMgr.systemSwVersionCB()
	case objects.ApiInfoState:
		retObj = getApiInfo(obj)
	default:
		break
	}
	return nil, retObj
}

func (clnt *LocalClient) ExecuteAction(obj actions.ActionObj) error {
	defer clnt.UnlockApiHandler()
	clnt.LockApiHandler()
	switch obj.(type) {
	case actions.SaveConfig, actions.ApplyConfig, actions.ForceApplyConfig, actions.ResetConfig:
		err := gClientMgr.executeConfigurationActionCB(obj)
		return err
	default:
		break
	}
	return nil
}

/*********************************************************************************************/
// Below methods are for localclient's own use only

type ApiCalls []objects.ConfigLogState

func (a ApiCalls) Len() int           { return len(a) }
func (a ApiCalls) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ApiCalls) Less(i, j int) bool { return a[i].SeqNum > a[j].SeqNum }

func getApiHistory(dbHdl *dbutils.DBUtil) (int64, int64, bool, []objects.ConfigObj) {
	var currMarker int64
	var count int64
	var retApiCalls []objects.ConfigObj
	ApiCallObj := objects.ConfigLogState{}
	currMarker = 0
	count = 1024
	err, count, next, more, apiCalls := dbHdl.GetBulkObjFromDb(ApiCallObj, currMarker, count)
	if err != nil {
		gClientMgr.logger.Err("Failed to get ConfigLog")
	} else {
		sortedApiCalls := make([]objects.ConfigLogState, len(apiCalls))
		for idx, object := range apiCalls {
			sortedApiCalls[idx] = object.(objects.ConfigLogState)
		}
		sort.Sort(ApiCalls(sortedApiCalls))
		retApiCalls = make([]objects.ConfigObj, len(sortedApiCalls))
		for idx, object := range sortedApiCalls {
			retApiCalls[idx] = object
		}
	}
	return count, next, more, retApiCalls
}

const (
	ApiInfoLevel_Access = iota + 1
	ApiInfoLevel_Version
	ApiInfoLevel_Type
	ApiInfoLevel_Details
)

type ObjJson struct {
	Access string `json:"Access"`
}

type Apis []string

func (a Apis) Len() int           { return len(a) }
func (a Apis) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Apis) Less(i, j int) bool { return a[i] < a[j] }

func getApiList(access string, objFile string) []string {
	var objMap map[string]ObjJson
	var apis Apis
	apis = make([]string, 0)
	bytes, err := ioutil.ReadFile(objFile)
	if err != nil {
		gClientMgr.logger.Info("Error in reading Object configuration file", objFile)
		return apis
	}
	err = json.Unmarshal(bytes, &objMap)
	if err != nil {
		gClientMgr.logger.Info("Error in unmarshaling data from ", objFile)
		return apis
	}
	for k, v := range objMap {
		if strings.Contains(v.Access, access) {
			apis = append(apis, strings.TrimSuffix(k, "State"))
		}
	}
	sort.Sort(apis)
	return apis
}

func getApiInfoType(level int, word string) (retObj objects.ApiInfoState) {
	switch word {
	case "config":
		retObj.Url = "/public/v1/config/"
		retObj.Info = getApiList("w", gClientMgr.paramsDir+"/genObjectConfig.json")
	case "state":
		retObj.Url = "/public/v1/state/"
		retObj.Info = getApiList("r", gClientMgr.paramsDir+"/genObjectConfig.json")
	case "action":
		retObj.Url = "/public/v1/action/"
		retObj.Info = getApiList("x", gClientMgr.paramsDir+"/genObjectAction.json")
	case "event":
		gClientMgr.logger.Info("Received ApiInfo call for /public/v1/event/ not supported")

	}
	return retObj
}

type ApiJson struct {
	Type  string `json:"type"`
	IsKey bool   `json:"isKey"`
}

func getApiInfoDetails(apiType, word string) (retObj objects.ApiInfoState) {
	var apiMap map[string]ApiJson
	var api string
	if apiType == "state" {
		api = word + "State"
	} else {
		api = word
	}
	apiDetailsFile := gClientMgr.paramsDir + "../models/" + api + "Members.json"
	bytes, err := ioutil.ReadFile(apiDetailsFile)
	if err != nil {
		gClientMgr.logger.Info("Error in reading file", apiDetailsFile)
		return retObj
	}
	err = json.Unmarshal(bytes, &apiMap)
	if err != nil {
		gClientMgr.logger.Info("Error in unmarshaling data from ", apiDetailsFile)
		return retObj
	}
	apiDetails := make([]string, 0)
	for k, v := range apiMap {
		apiField := k + "  " + v.Type
		if v.IsKey {
			apiField = apiField + "  " + "(key)"
		}
		apiDetails = append(apiDetails, apiField)
	}
	retObj.Url = "/public/v1/" + apiType + "/" + api
	retObj.Info = apiDetails
	return retObj
}

func getApiInfo(obj objects.ConfigObj) (retObj objects.ConfigObj) {
	var apiInfoLevel int
	var apiInfoWord string
	var apiType string
	apiInfo := obj.(objects.ApiInfoState)
	url := apiInfo.Url
	urlWords := strings.Split(url, "/")
	for _, word := range urlWords {
		if word != "" {
			apiInfoWord = word
			switch word {
			case "public":
				apiInfoLevel = ApiInfoLevel_Access
			case "v1":
				apiInfoLevel = ApiInfoLevel_Version
			case "config", "state", "action", "event":
				apiInfoLevel = ApiInfoLevel_Type
				apiType = word
			default:
				apiInfoLevel = ApiInfoLevel_Details

			}
		}
	}
	switch apiInfoLevel {
	case ApiInfoLevel_Type:
		retObj = getApiInfoType(apiInfoLevel, apiInfoWord)
	case ApiInfoLevel_Details:
		retObj = getApiInfoDetails(apiType, apiInfoWord)
	default:
		gClientMgr.logger.Info("Received ApiInfo call", apiInfoLevel, apiInfoWord, "not supported")
	}
	gClientMgr.logger.Info("Received ApiInfo call", apiInfoLevel, apiInfoWord)
	return retObj
}
