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

package actions

import (
	"config/clients"
	"config/objects"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	modelActions "models/actions"
	modelObjs "models/objects"
	"net/http"
	"os"
	"strings"
	"utils/logging"
)

//
// Actions are methods exposed by various daemons. These may have an object as parameter.
// The only methods supported on these actions would be POST methods
//

//
// ActionManager provides the following methods for rest of the config manager subsystem
//  -- Initialize
//  -- DeInitialize
//  -- RegisterActions
//  -- PerformAction
//

type ActionMgr struct {
	logger           *logging.Writer
	paramsDir        string
	dbHdl            *objects.DbHandler
	ObjHdlMap        map[string]ActionObjInfo
	clientMgr        *clients.ClientMgr
	objectMgr        *objects.ObjectMgr
	applyConfigOrder []string
}

type ConfigOrder struct {
	Order []string `json:"Order"`
}

var gActionMgr *ActionMgr

// SR error codes
const (
	SRFail              = 0
	SRSuccess           = 1
	SRSystemNotReady    = 2
	SRRespMarshalErr    = 3
	SRNotFound          = 4
	SRIdStoreFail       = 5
	SRIdDeleteFail      = 6
	SRServerError       = 7
	SRObjHdlError       = 8
	SRObjMapError       = 9
	SRBulkGetTooLarge   = 10
	SRNoContent         = 11
	SRAuthFailed        = 12
	SRAlreadyConfigured = 13
	SRUpdateKeyError    = 14
	SRUpdateNoChange    = 15
)

// This structure represents the json layout for action objects
type ActionObjJson struct {
	Owner string `json:"Owner"`
}

// This structure represents the in memory layout of all the action object handlers
type ActionObjInfo struct {
	Owner clients.ClientIf
}

func CreateActionMap() {
	for actionName, action := range modelActions.GenActionObjectMap {
		modelActions.ActionObjectMap[actionName] = action
	}
}

func InitializeActionMgr(paramsDir string, infoFiles []string, logger *logging.Writer, dbHdl *objects.DbHandler, objectMgr *objects.ObjectMgr, clientMgr *clients.ClientMgr) *ActionMgr {
	mgr := new(ActionMgr)
	mgr.paramsDir = paramsDir
	if logger == nil {
		logger.Err("logger nil")
		return nil
	}
	mgr.logger = logger
	if clientMgr == nil {
		logger.Err("clientMgr nil")
		return nil
	}
	mgr.clientMgr = clientMgr
	if objectMgr == nil {
		logger.Err("objectMgr nil")
		return nil
	}
	mgr.objectMgr = objectMgr
	if dbHdl == nil {
		logger.Err("dbHdl nil")
		return nil
	}
	mgr.dbHdl = dbHdl
	if rc := mgr.InitializeActionObjectHandles(infoFiles); !rc {
		logger.Err("Error in initializing action object handles")
		return nil
	}
	mgr.applyConfigOrder = make([]string, 0)
	if err := mgr.ReadConfigOrder(); err != nil {
		logger.Err("Error in reading config order file")
	}
	gActionMgr = mgr
	return mgr
}

func (mgr *ActionMgr) InitializeActionObjectHandles(infoFiles []string) bool {
	var actionMap map[string]ActionObjJson

	mgr.ObjHdlMap = make(map[string]ActionObjInfo)
	for _, objFile := range infoFiles {
		bytes, err := ioutil.ReadFile(objFile)
		if err != nil {
			mgr.logger.Err("Error in reading Action configuration file", objFile)
			return false
		}
		err = json.Unmarshal(bytes, &actionMap)
		if err != nil {
			mgr.logger.Err("Error in unmarshaling data from ", objFile)
			return false
		}

		for k, v := range actionMap {
			mgr.logger.Debug("For Action [", k, "] Primary owner is [", v.Owner, "] ")
			key := strings.ToLower(k)
			entry := new(ActionObjInfo)
			if mgr.clientMgr != nil {
				entry.Owner = mgr.clientMgr.Clients[v.Owner]
			}
			mgr.ObjHdlMap[key] = *entry
		}
	}
	return true
}

func (mgr *ActionMgr) ReadConfigOrder() error {
	var configOrder ConfigOrder
	bytes, err := ioutil.ReadFile(mgr.paramsDir + "/configOrder.json")
	if err != nil {
		mgr.logger.Err("Error in reading configuration order file")
		return err
	}
	err = json.Unmarshal(bytes, &configOrder)
	if err != nil {
		mgr.logger.Err("Error in unmarshaling data from configOrder.json")
		return err
	}
	for _, objName := range configOrder.Order {
		mgr.applyConfigOrder = append(mgr.applyConfigOrder, objName)
	}
	return nil
}

func (mgr *ActionMgr) GetAllActions() []string {
	retList := make([]string, 0)
	for key, _ := range modelActions.ActionObjectMap {
		retList = append(retList, key)
	}
	return retList
}

func GetActionObj(r *http.Request, obj modelActions.ActionObj) (body []byte, retobj modelActions.ActionObj, err error) {
	//var ret_obj map[string]modelActions.DummyStruct
	if obj == nil {
		err = errors.New("Action Object is nil")
		return body, retobj, err
	}
	//	gActionMgr.logger.Debug("GetActionObj r:", r, " obj:", obj)
	if r != nil {
		body, err = ioutil.ReadAll(io.LimitReader(r.Body, r.ContentLength))
		gActionMgr.logger.Debug("err:", err, " body:", body)
		if err != nil {
			return body, retobj, err
		}
		if err = r.Body.Close(); err != nil {
			return body, retobj, err
		}
	} else {
		return body, retobj, err
	}
	retobj, err = obj.UnmarshalAction(body)
	if err != nil {
		gActionMgr.logger.Info("UnmarshalObject returned error", err, " for ojbect info", retobj)
	}
	return body, retobj, err
}

func CreateConfig(resource string, body json.RawMessage) {
	var errCode int
	var success bool
	var err error
	var obj modelObjs.ConfigObj
	var objKey string
	errCode = SRSuccess

	gActionMgr.logger.Debug("Create config resource:", resource)
	if objHdl, ok := modelObjs.ConfigObjectMap[strings.ToLower(resource)]; ok {
		if obj, err = objHdl.UnmarshalObject(body); err == nil {
			updateKeys, _ := objects.GetUpdateKeys(body)
			if len(updateKeys) == 0 {
				errCode = SRNoContent
				gActionMgr.logger.Err("Nothing to configure")
			} else {
				objKey = obj.GetKey()
				_, err = gActionMgr.dbHdl.GetUUIDFromObjKey(objKey)
				if err == nil {
					gActionMgr.logger.Debug("Config object is present, update it")
					UpdateConfig(resource, body)
					return
				}
			}
			if errCode != SRSuccess {
				gActionMgr.logger.Debug("errcode not success, return")
				return
			}
			if gActionMgr.objectMgr.ObjHdlMap == nil {
				gActionMgr.logger.Debug("objHdlMap nil")
				return
			}
			_, ok = gActionMgr.objectMgr.ObjHdlMap[strings.ToLower(resource)]
			if !ok {
				gActionMgr.logger.Debug("objhdlmap for resource:", resource, " nil")
				return
			}
			resourceOwner := gActionMgr.objectMgr.ObjHdlMap[strings.ToLower(resource)].Owner
			if resourceOwner.IsConnectedToServer() == false {
				gActionMgr.logger.Debug("Not connected to resourceOwner:", resourceOwner)
				return
			}
			gActionMgr.logger.Debug("Create:", resource, " resourceOwner:", resourceOwner, " obj:", obj)
			err, success = resourceOwner.CreateObject(obj, gActionMgr.dbHdl.DBUtil)
			if err == nil && success == true {
				_, dbErr := gActionMgr.dbHdl.StoreUUIDToObjKeyMap(objKey)
				if dbErr == nil {
					errCode = SRSuccess
				} else {
					errCode = SRIdStoreFail
					gActionMgr.logger.Err(fmt.Sprintln("Failed to store UuidToKey map ", obj, dbErr))
				}
			} else {
				errCode = SRServerError
				gActionMgr.logger.Err(fmt.Sprintln("Failed to create object: ", obj, " due to error: ", err))
			}
		} else {
			errCode = SRObjHdlError
			gActionMgr.logger.Err(fmt.Sprintln("Failed to get object handle from http request ", objHdl, resource, err))
		}
	} else {
		errCode = SRObjMapError
		gActionMgr.logger.Err("Failed to get ObjectMap " + resource)
	}
}

func UpdateConfig(resource string, body json.RawMessage) {
	var success bool
	var err error
	var obj modelObjs.ConfigObj
	var objKey string

	gActionMgr.logger.Debug("Update config resource:", resource)
	if objHdl, ok := modelObjs.ConfigObjectMap[strings.ToLower(resource)]; ok {
		if obj, err = objHdl.UnmarshalObject(body); err == nil {
			objKey = obj.GetKey()
			updateKeys, _ := objects.GetUpdateKeys(body)
			dbObj, gerr := obj.GetObjectFromDb(objKey, gActionMgr.dbHdl.DBUtil)
			if gerr != nil {
				gActionMgr.logger.Err("entry not found in DB")
				return
			}
			_, err = gActionMgr.dbHdl.GetUUIDFromObjKey(objKey)
			diff, _ := obj.CompareObjectsAndDiff(updateKeys, dbObj)
			anyUpdated := false
			for _, updated := range diff {
				if updated == true {
					anyUpdated = true
					break
				}
			}
			if anyUpdated == false {
				gActionMgr.logger.Err("No updates to be made")
				return
			}
			mergedObj, _ := obj.MergeDbAndConfigObj(dbObj, diff)
			mergedObjKey := mergedObj.GetKey()
			if objKey == mergedObjKey {
				resourceOwner := gActionMgr.objectMgr.ObjHdlMap[strings.ToLower(resource)].Owner
				if resourceOwner.IsConnectedToServer() == false {
					return
				}

				err, success = resourceOwner.UpdateObject(dbObj, mergedObj, diff, nil, objKey, gActionMgr.dbHdl.DBUtil)
				if err == nil && success == true {
					_, dbErr := gActionMgr.dbHdl.StoreUUIDToObjKeyMap(objKey)
					if dbErr == nil {
					} else {
						gActionMgr.logger.Err(fmt.Sprintln("Failed to store UuidToKey map ", obj, dbErr))
					}
				} else {
					gActionMgr.logger.Err(fmt.Sprintln("Failed to update object: ", obj, " due to error: ", err))
				}
			} else {
				gActionMgr.logger.Err(fmt.Sprintln("Failed to get object handle from http request ", objHdl, resource, err))
			}
		} else {
			fmt.Println("Failed to get object map")
			gActionMgr.logger.Err("Failed to get ObjectMap " + resource)
		}
	}
}

func DeleteConfig(resource string) {
	objMap, ok := gActionMgr.objectMgr.ObjHdlMap[strings.ToLower(resource)]
	if !ok {
		gActionMgr.logger.Debug("Object ", resource, " doesnt exist in ObjHdlMap")
		return
	}
	if objMap.Owner == nil {
		gActionMgr.logger.Debug("Owner for:", resource, "is nil")
		return
	}
	if objMap.Owner.IsConnectedToServer() == false {
		gActionMgr.logger.Err("ResetConfig: Not connected to daemon " + resource)
		return
	}
	if strings.Contains(objMap.Access, "w") {
		gActionMgr.logger.Debug("Get db objects for  ", resource)
		if objHdl, ok := modelObjs.ConfigObjectMap[strings.ToLower(resource)]; ok {
			_, obj, _ := objects.GetConfigObjFromJsonData(nil, objHdl)
			currentIndex := int64(0)
			objCount := int64(1024)
			err, _, _, _, objs := gActionMgr.dbHdl.GetBulkObjFromDb(obj, currentIndex, objCount)
			if err != nil {
				gActionMgr.logger.Debug("Failed to do getBulk object ", objMap.Owner)
			}
			gActionMgr.logger.Debug("No of objects collected ", len(objs))
			for _, obj := range objs {
				objKey := obj.GetKey()
				gActionMgr.logger.Debug("Obj ", obj, " key ", objKey)
				if !objMap.AutoCreate && !objMap.AutoDiscover {
					err, success := objMap.Owner.DeleteObject(obj, objKey, gActionMgr.dbHdl.DBUtil)
					if err == nil && success == true {
						gActionMgr.logger.Debug("Delete UUID to objectKeyMap")
						uuid, er := gActionMgr.dbHdl.GetUUIDFromObjKey(objKey)
						if er == nil {
							err = gActionMgr.dbHdl.DeleteUUIDToObjKeyMap(uuid, objKey)
							if err != nil {
								gActionMgr.logger.Err("Failed to delete uuid map ", uuid)
							}
						}
					}
				} else {
					defaultObjKey := objKey + "Default"
					defaultObj, err := gActionMgr.dbHdl.GetObjectFromDb(obj, defaultObjKey)
					if err == nil {
						gActionMgr.logger.Debug("DeleteConfig: update to default - ", resource)
						diff, _ := gActionMgr.dbHdl.CompareObjectDefaultAndDiff(obj, defaultObj)
						anyUpdated := false
						for _, updated := range diff {
							if updated == true {
								anyUpdated = true
								break
							}
						}
						if anyUpdated == true {
							err, success := objMap.Owner.UpdateObject(obj, defaultObj, diff, nil, objKey, gActionMgr.dbHdl.DBUtil)
							if success == false {
								gActionMgr.logger.Err("DeleteConfig: failed to update to default " + objKey + " Error: " + err.Error())
							}
						}
					}
				}
			}
		}
	}
}

func ApplyConfigObject(data modelActions.ApplyConfig) {
	for _, applyResource := range gActionMgr.applyConfigOrder {
		for key, value := range data.ConfigData {
			if applyResource != key {
				continue
			}
			gActionMgr.logger.Debug("ApplyConfig for:", key, "value:", value, " resoure:", applyResource)
			for _, v := range value {
				if _, err := json.Marshal(v); err == nil {
					CreateConfig(key, v)
				}
			}
		}
	}
}

func ForceApplyConfigObject(data modelActions.ForceApplyConfig) {
	appliedConfigs := make(map[string]bool)
	for _, applyResource := range gActionMgr.applyConfigOrder {
		for key, value := range data.ConfigData {
			if applyResource != key {
				continue
			}
			appliedConfigs[applyResource] = true
			gActionMgr.logger.Debug("ApplyConfig for:", key, "value:", value, " resoure:", applyResource)
			for _, v := range value {
				if _, err := json.Marshal(v); err == nil {
					CreateConfig(key, v)
				}
			}
		}
	}
	for index := len(gActionMgr.applyConfigOrder) - 1; index >= 0; index-- {
		objName := gActionMgr.applyConfigOrder[index]
		if appliedConfigs[objName] != true {
			gActionMgr.logger.Debug("Reset configs for:", objName)
			DeleteConfig(objName)
		}
	}
}

func SaveConfigObject(data modelActions.SaveConfigObj, resource string) error {
	gActionMgr.logger.Debug("SaveConfigObject for resource:", resource)
	objHdl, ok := modelObjs.ConfigObjectMap[strings.ToLower(resource)]
	if !ok {
		gActionMgr.logger.Err("objHdl nil for", resource)
		return errors.New("objHdl Nil for " + resource)
	}
	_, obj, err := objects.GetConfigObjFromJsonData(nil, objHdl)
	if err != nil {
		gActionMgr.logger.Err("GetConfigObj return err: " + err.Error())
		return errors.New("getConfigObj return err")
	}
	var configObjects []modelObjs.ConfigObj
	currentIndex := int64(0)
	objCount := int64(1024)
	err, objCount, _, _, configObjects = gActionMgr.dbHdl.GetBulkObjFromDb(obj, currentIndex, objCount)
	if err != nil {
		gActionMgr.logger.Err("GetBulkObjFromDB returned error:" + err.Error())
		return errors.New("GetBulkObjFromDb returned error")
	}
	if objCount == 0 {
		gActionMgr.logger.Debug("No objects of type:", resource, " configured")
		return nil
	}
	if data.ConfigData[resource] == nil {
		data.ConfigData[resource] = make([]interface{}, 0)
	}
	for _, configObject := range configObjects {
		data.ConfigData[resource] = append(data.ConfigData[resource], configObject)
	}
	return nil

}

func ResetConfigObject(data modelActions.ResetConfig) (err error) {
	gActionMgr.logger.Debug("Start config reset")
	for index := len(gActionMgr.applyConfigOrder) - 1; index >= 0; index-- {
		objName := gActionMgr.applyConfigOrder[index]
		gActionMgr.logger.Debug("Reset configs for:", objName)
		DeleteConfig(objName)
	}
	return nil
}

func OpenConfigFile(cfgFileName string) (fo *os.File, err error) {
	gActionMgr.logger.Debug("Full config file : ", cfgFileName)
	_, err = os.Stat(cfgFileName)
	if os.IsNotExist(err) {
		gActionMgr.logger.Debug(cfgFileName, " not present, create it")
		fo, err = os.Create(cfgFileName)
		if err != nil {
			gActionMgr.logger.Err("Error :" + err.Error() + " when creating file: " + cfgFileName)
			return fo, err
		}
	} else if err == nil {
		// open cfg file
		gActionMgr.logger.Debug("cfgFile present, open it for update")
		fo, err = os.OpenFile(cfgFileName, os.O_RDWR, 0666)
		if err != nil {
			gActionMgr.logger.Err("Error:", err, "when opening cfgFile: "+cfgFileName)
			return fo, err
		}
	} else {
		gActionMgr.logger.Err("Error:", err, " when handling the cfgFile: "+cfgFileName)
		return fo, err
	}
	return fo, err
}

func ExecuteConfigurationAction(obj modelActions.ActionObj) (err error) {
	gActionMgr.logger.Debug("local client Execute action obj: ", obj)
	if gActionMgr == nil {
		gActionMgr.logger.Err("Action mgr not initialized")
		return err
	}
	switch obj.(type) {
	case modelActions.ApplyConfig:
		gActionMgr.logger.Debug("ApplyConfig")
		data := obj.(modelActions.ApplyConfig)
		ApplyConfigObject(data)
	case modelActions.ForceApplyConfig:
		gActionMgr.logger.Debug("ForceApplyConfig")
		data := obj.(modelActions.ForceApplyConfig)
		ForceApplyConfigObject(data)
	case modelActions.SaveConfig:
		gActionMgr.logger.Debug("SaveConfig")
		var fo *os.File
		var err error
		data := obj.(modelActions.SaveConfig)
		fileName := data.FileName
		gActionMgr.logger.Debug("FileName:", fileName)
		if fileName == "" {
			gActionMgr.logger.Debug("FileName not set, setting it to default startup-config")
			fileName = gActionMgr.paramsDir + "../" + "startup-config.json"
		} else {
			if !strings.HasPrefix(fileName, "/") {
				fileName = gActionMgr.paramsDir + "../" + fileName
			}
		}
		if !strings.HasSuffix(fileName, ".json") {
			fileName = fileName + ".json"
		}
		// open config file
		fo, err = OpenConfigFile(fileName)
		if err != nil {
			gActionMgr.logger.Err("error with opening file to save config " + fileName + " err: " + err.Error())
			return err
		}
		// close fo on exit and check for its returned error
		defer func() {
			if err := fo.Close(); err != nil {
				panic(err)
			}
		}()
		var wdata modelActions.SaveConfigObj
		wdata.ConfigData = make(map[string][]interface{})
		for _, applyResource := range gActionMgr.applyConfigOrder {
			SaveConfigObject(wdata, applyResource)
		}
		js, err := json.MarshalIndent(wdata, "", "    ")
		if err != nil {
			gActionMgr.logger.Err("json marshal returned error: " + err.Error())
			return err
		}
		gActionMgr.logger.Debug("js:", string(js))
		_, err = fo.Write(js)
		if err != nil {
			gActionMgr.logger.Err("Error writing: " + err.Error())
			return err
		}

	case modelActions.ResetConfig:
		gActionMgr.logger.Debug("Action resolved as ResetConfig")
		data := obj.(modelActions.ResetConfig)
		ResetConfigObject(data)
	}
	return err
}
