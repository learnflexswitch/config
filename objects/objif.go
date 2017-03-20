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

package objects

import (
	"config/clients"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"models/events"
	"models/objects"
	"net/http"
	"strings"
	"utils/commonDefs"
	"utils/logging"
)

type AutoCreateStruct struct {
	ObjList []string
}

type AutoDiscoverStruct struct {
	ObjList []string
}

type ObjectMgr struct {
	logger             *logging.Writer
	dbHdl              *DbHandler
	ObjHdlMap          map[string]ConfigObjInfo
	clientMgr          *clients.ClientMgr
	AutoCreateObjMap   map[string]AutoCreateStruct
	AutoDiscoverObjMap map[string]AutoDiscoverStruct
}

type PatchOp map[string]*json.RawMessage

// Patch is an ordered collection of patch-ops.
type Patch []PatchOp

var gObjectMgr *ObjectMgr

//
// This structure represents the json layout for config objects
type ConfigObjJson struct {
	Owner         string   `json:"Owner"`
	Access        string   `json:"Access"`
	Listeners     []string `json:"Listeners"`
	AutoCreate    bool     `json:"autoCreate"`
	AutoDiscover  bool     `json:"autoDiscover"`
	LinkedObjects []string `json:"linkedObjects"`
}

//
// This structure represents the in memory layout of all the config object handlers
type ConfigObjInfo struct {
	Owner         clients.ClientIf
	Access        string
	AutoCreate    bool
	AutoDiscover  bool
	LinkedObjects []string
	Listeners     []clients.ClientIf
}

func resolveUnmarshalErr(data []byte, err error) string {
	if e, ok := err.(*json.UnmarshalTypeError); ok {
		var i int
		for i = int(e.Offset) - 1; i != -1 && data[i] != '\n' && data[i] != ','; i-- {
		}
		info := strings.TrimSpace(string(data[i+1 : int(e.Offset)]))
		return e.Error() + info
	}
	if e, ok := err.(*json.UnmarshalFieldError); ok {
		return e.Error()
	}
	if e, ok := err.(*json.InvalidUnmarshalError); ok {
		return e.Error()
	}
	return err.Error()
}

func GetConfigObjFromJsonData(r *http.Request, obj objects.ConfigObj) (body []byte, retobj objects.ConfigObj, err error) {
	if obj == nil {
		err = errors.New("Config Object is nil")
		return body, retobj, err
	}
	if r != nil {
		body, err = ioutil.ReadAll(io.LimitReader(r.Body, commonDefs.MAX_JSON_LENGTH))
		if err != nil {
			return body, retobj, err
		}
		if err = r.Body.Close(); err != nil {
			return body, retobj, err
		}
	}
	retobj, err = obj.UnmarshalObject(body)
	if err != nil {
		errStr := resolveUnmarshalErr(body, err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("UnmarshalObject returned error", err, "for object info", retobj)
	}
	return body, retobj, err
}

func GetConfigObjFromQueryData(r *http.Request, obj objects.ConfigObj) (body []byte, retobj objects.ConfigObj, err error) {
	if obj == nil {
		err = errors.New("Config Object is nil")
		return body, retobj, err
	}
	queryMap := r.URL.Query()
	if queryMap == nil {
		err = errors.New("Empty query data")
		return body, retobj, err
	}
	retobj, err = obj.UnmarshalObjectData(queryMap)
	if err != nil || retobj == nil {
		gObjectMgr.logger.Err("UnmarshalObjectData returned error", err, "for object info", retobj)
		return body, retobj, err
	}
	body, err = json.Marshal(retobj)
	if err != nil {
		gObjectMgr.logger.Err("Marshal retobj returned error", err, "for object info", retobj)
	}
	return body, retobj, err
}

func GetEventObj(r *http.Request, obj events.EventObj) (body []byte, retobj events.EventObj, err error) {
	if obj == nil {
		err = errors.New("Event Object is nil")
		return body, retobj, err
	}
	if r != nil {
		body, err = ioutil.ReadAll(io.LimitReader(r.Body, commonDefs.MAX_JSON_LENGTH))
		if err != nil {
			return body, retobj, err
		}
		if err = r.Body.Close(); err != nil {
			return body, retobj, err
		}
	}
	retobj, err = obj.UnmarshalObject(body)
	if err != nil {
		errStr := resolveUnmarshalErr(body, err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("UnmarshalObject returned error", err, "for object info", retobj)
	}
	return body, retobj, err
}

func GetUpdateKeys(body []byte) (map[string]bool, error) {
	var objmap map[string]*json.RawMessage
	var err error
	updateKeys := make(map[string]bool)

	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return updateKeys, err
	}
	for key, _ := range objmap {
		updateKeys[key] = true
	}
	return updateKeys, err
}

func CreateObjectMap() {
	//objects.ConfigObjectMap
	for objName, obj := range objects.GenConfigObjectMap {
		objects.ConfigObjectMap[objName] = obj
	}
}

func GetValue(op PatchOp, obj objects.ConfigObj) (valueObj interface{}, err error) {
	value, ok := op["value"]
	if !ok {
		gObjectMgr.logger.Info("No value")
		return nil, errors.New("Unknown")
	}
	//valueStr,err = obj.UnmarshalObject(*value)
	gObjectMgr.logger.Debug("value: ", string(*value))
	err = json.Unmarshal([]byte(*value), &valueObj)
	if err != nil {
		errStr := resolveUnmarshalErr([]byte(*value), err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("error unmarshaling value:", err)
		return nil, err
	}
	return valueObj, err
}
func GetPatch(patches []byte) (patch Patch, err error) {
	err = json.Unmarshal(patches, &patch)
	if err != nil {
		errStr := resolveUnmarshalErr(patches, err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("error unmarshaling patches:", err)
		return patch, err
	}
	return patch, err
}
func GetPath(op PatchOp) (pathStr string, err error) {
	path, ok := op["path"]
	if !ok {
		gObjectMgr.logger.Info("No path")
		return pathStr, errors.New("Unknown")
	}
	err = json.Unmarshal(*path, &pathStr)
	if err != nil {
		errStr := resolveUnmarshalErr(*path, err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("error unmarshaling path:", err)
		return pathStr, err
	}
	pathStr = strings.Split(pathStr, "/")[1]
	return pathStr, err
}
func GetOp(patchOp PatchOp) (opStr string, err error) {
	op, ok := patchOp["op"]
	if !ok {
		gObjectMgr.logger.Info("No op")
		return opStr, errors.New("Unknown")
	}
	err = json.Unmarshal(*op, &opStr)
	if err != nil {
		errStr := resolveUnmarshalErr(*op, err)
		err = errors.New(errStr)
		gObjectMgr.logger.Err("error unmarshaling patches:", err)
		return opStr, err
	}
	return opStr, err
}
func InitializeObjectMgr(infoFiles []string, logger *logging.Writer, dbHdl *DbHandler, clientMgr *clients.ClientMgr) *ObjectMgr {
	mgr := new(ObjectMgr)
	mgr.logger = logger
	mgr.dbHdl = dbHdl
	mgr.clientMgr = clientMgr
	if rc := mgr.InitializeObjectHandles(infoFiles); !rc {
		logger.Err("Error in initializing object handles")
		return nil
	}
	gObjectMgr = mgr
	return mgr
}

//
//  This method reads the config file and connects to all the clients in the list
//
func (mgr *ObjectMgr) InitializeObjectHandles(infoFiles []string) bool {
	var objMap map[string]ConfigObjJson
	mgr.ObjHdlMap = make(map[string]ConfigObjInfo)
	mgr.AutoCreateObjMap = make(map[string]AutoCreateStruct)
	mgr.AutoDiscoverObjMap = make(map[string]AutoDiscoverStruct)
	for _, objFile := range infoFiles {
		bytes, err := ioutil.ReadFile(objFile)
		if err != nil {
			mgr.logger.Info("Error in reading Object configuration file", objFile)
			return false
		}
		err = json.Unmarshal(bytes, &objMap)
		if err != nil {
			mgr.logger.Info("Error in unmarshaling data from ", objFile)
		}

		for k, v := range objMap {
			mgr.logger.Debug("For Object [", k, "] Primary owner is [", v.Owner, "] access is",
				v.Access, " Auto Create ", v.AutoCreate, " Auto Discover ", v.AutoDiscover)
			key := strings.ToLower(k)
			entry := new(ConfigObjInfo)
			entry.Owner = mgr.clientMgr.Clients[v.Owner]
			entry.Access = v.Access
			entry.AutoCreate = v.AutoCreate
			entry.AutoDiscover = v.AutoDiscover
			for _, lsnr := range v.Listeners {
				entry.Listeners = append(entry.Listeners, mgr.clientMgr.Clients[lsnr])
			}
			entry.LinkedObjects = append(entry.LinkedObjects, v.LinkedObjects...)
			mgr.ObjHdlMap[key] = *entry

			if v.AutoCreate == true {
				ent, _ := mgr.AutoCreateObjMap[v.Owner]
				ent.ObjList = append(ent.ObjList, key)
				mgr.AutoCreateObjMap[v.Owner] = ent
			}

			if v.AutoDiscover == true {
				ent, _ := mgr.AutoDiscoverObjMap[v.Owner]
				ent.ObjList = append(ent.ObjList, key)
				mgr.AutoDiscoverObjMap[v.Owner] = ent
			}
		}
	}
	return true
}
func (mgr *ObjectMgr) GetConfigObjHdlMap() map[string]ConfigObjInfo {
	return mgr.ObjHdlMap
}

func (mgr *ObjectMgr) GetAutoDiscoverObjMap() map[string]AutoDiscoverStruct {
	return mgr.AutoDiscoverObjMap
}
