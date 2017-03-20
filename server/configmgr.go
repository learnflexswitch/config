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
	"config/actions"
	"config/apis"
	"config/clients"
	"config/objects"
	"encoding/json"
	"fmt"
	"io/ioutil"
	modelObjs "models/objects"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"utils/logging"
)

type ConfigMgr struct {
	logger       *logging.Writer
	paramsDir    string
	dbHdl        *objects.DbHandler
	bringUpTime  time.Time
	swVersion    SwVersion
	ApiMgr       *apis.ApiMgr
	clientMgr    *clients.ClientMgr
	objectMgr    *objects.ObjectMgr
	actionMgr    *actions.ActionMgr
	clientNameCh chan string
}

var gConfigMgr *ConfigMgr

const (
	MAX_COUNT_AUTO_DISCOVER_OBJ int64 = 1000
)

type SysProfile struct {
	API_Port int `json:"API_Port"`
}

// Get the http port on which rest api calls will be received
func GetConfigHandlerPort(paramsDir string) (bool, string) {
	var sysProfile SysProfile
	var port string

	sysProfileFile := paramsDir + "systemProfile.json"
	bytes, err := ioutil.ReadFile(sysProfileFile)
	if err != nil {
		gConfigMgr.logger.Err("Error in reading globals file", sysProfileFile)
		return false, port
	}

	err = json.Unmarshal(bytes, &sysProfile)
	if err != nil {
		gConfigMgr.logger.Err("Failed to Unmarshall Json")
		return false, port
	}
	port = strconv.Itoa(sysProfile.API_Port)
	return true, port
}

//
// This function would work as a classical constructor for the
// configMgr object
//
func NewConfigMgr(paramsDir string, logger *logging.Writer) *ConfigMgr {
	mgr := new(ConfigMgr)
	mgr.logger = logger
	mgr.paramsDir = paramsDir

	mgr.dbHdl = objects.InstantiateDbIf(logger)
	if mgr.dbHdl == nil {
		logger.Err("Error initializing configMgr dbHdl")
		return nil
	}

	mgr.clientMgr = clients.InitializeClientMgr(paramsDir, logger,
		GetSystemStatus,
		GetSystemSwVersion,
		actions.ExecuteConfigurationAction)
	if mgr.clientMgr == nil {
		logger.Err("Error initializing clientMgr")
		return nil
	}

	objects.CreateObjectMap()
	objectConfigFiles := [...]string{paramsDir + "/genObjectConfig.json"}
	mgr.objectMgr = objects.InitializeObjectMgr(objectConfigFiles[:], logger,
		mgr.dbHdl, mgr.clientMgr)
	if mgr.objectMgr == nil {
		logger.Err("Error initializing objectMgr")
		return nil
	}

	actions.CreateActionMap()
	actionConfigFiles := [...]string{paramsDir + "/genObjectAction.json"}
	mgr.actionMgr = actions.InitializeActionMgr(paramsDir, actionConfigFiles[:], logger,
		mgr.dbHdl, mgr.objectMgr, mgr.clientMgr)
	if mgr.actionMgr == nil {
		logger.Err("Error initializing actionMgr")
		return nil
	}

	mgr.ApiMgr = apis.InitializeApiMgr(paramsDir, logger,
		mgr.dbHdl, mgr.clientMgr, mgr.objectMgr, mgr.actionMgr)
	if mgr.ApiMgr == nil {
		logger.Err("Error initializing ApiMgr")
		return nil
	}

	mgr.ApiMgr.InitializeRestRoutes()
	mgr.ApiMgr.InitializeActionRestRoutes()
	mgr.ApiMgr.InitializeEventRestRoutes()
	mgr.ApiMgr.InstantiateRestRtr()

	mgr.bringUpTime = time.Now()
	// Initialize channel to receive connected client name.
	// When confd connects to a client, it creates autocreate objects owned by that client and
	// stores default logging level for that client in DB, if it does not exist.
	// Autocreate objects and logging objects can only be updated by user.
	// Also, confd discovers all the discoverable objects from that client and stores in DB.
	mgr.clientNameCh = make(chan string, 10)
	logger.Info("Initialization Done!")

	mgr.ReadSystemSwVersion()
	go mgr.AutoCreateConfigObjects()
	go mgr.clientMgr.ListenToClientStateChanges()
	go mgr.clientMgr.ConnectToAllClients(mgr.clientNameCh)
	go mgr.SigHandler()
	gConfigMgr = mgr

	return mgr
}

func (mgr *ConfigMgr) SigHandler() {
	sigChan := make(chan os.Signal, 1)
	signalList := []os.Signal{syscall.SIGHUP}
	signal.Notify(sigChan, signalList...)

	for {
		select {
		case signal := <-sigChan:
			switch signal {
			case syscall.SIGHUP:
				mgr.logger.Info("Exting!!!")
				mgr.dbHdl.DisconnectDbIf()
				mgr.clientMgr.DisconnectFromAllClients()
				os.Exit(0)
			default:
			}
		}
	}
}

func (mgr *ConfigMgr) storeUUID(key string) {
	_, err := mgr.dbHdl.StoreUUIDToObjKeyMap(key)
	if err != nil {
		mgr.logger.Err("Failed to store uuid map for key " + key + "Error: " + err.Error())
	}
}

func (mgr *ConfigMgr) ConfigureGlobalConfig(clientName string) {
	var obj modelObjs.ConfigObj
	var err error
	if ent, ok := mgr.objectMgr.AutoCreateObjMap[clientName]; ok {
		mgr.logger.Err("AutoCreate : ", clientName, ent)
		for _, resource := range ent.ObjList {
			if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
				var body []byte
				obj, _ = objHdl.UnmarshalObject(body)
				objKey := mgr.dbHdl.GetKey(obj)
				_, err = mgr.dbHdl.GetObjectFromDb(obj, objKey)
				if err != nil {
					client, exist := mgr.clientMgr.Clients[clientName]
					if exist {
						err, success := client.CreateObject(obj, mgr.dbHdl.DBUtil)
						if err == nil && success == true {
							mgr.storeUUID(obj.GetKey())
							err = mgr.dbHdl.StoreObjectDefaultInDb(obj)
							if err != nil {
								mgr.logger.Err(fmt.Sprintln("Failed to store"+resource+" default config in DB ", obj, err))
							}
						} else {
							mgr.logger.Err(fmt.Sprintln("Failed to create "+resource+" ", obj, err))
						}
					}
				}
			}
		}
	}
}

func (mgr *ConfigMgr) AutoCreateConfigObjects() {
	var clientNameList []string
	for {
		select {
		case clientName := <-mgr.clientNameCh:
			switch clientName {
			case "Client_Init_Done":
				//Perform auto create (equivalent to cfg action) only after all clients are connected
				for _, name := range clientNameList {
					mgr.ConfigureGlobalConfig(name)
				}
				close(mgr.clientNameCh)
				mgr.clientMgr.SystemReady = true
				return
			default:
				//Cache list of client names to use for autocreate
				clientNameList = append(clientNameList, clientName)
				mgr.logger.Info("Do Global Init and Discover objects for Client: " + clientName)
				mgr.ConstructSystemParam(clientName)
				mgr.AutoDiscoverObjects(clientName)
				mgr.ConfigureComponentLoggingLevel(clientName)
				mgr.logger.Info("Done Global Init and Discover objects for Client: " + clientName)
			}
		}
	}
}

func (mgr *ConfigMgr) AutoDiscoverObjects(clientName string) {
	mgr.logger.Debug("AutoDiscover for: ", clientName)
	if ent, ok := mgr.objectMgr.AutoDiscoverObjMap[clientName]; ok {
		for _, resource := range ent.ObjList {
			mgr.logger.Debug("AutoDiscover: ", resource)
			if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
				var objs []modelObjs.ConfigObj
				var err error
				_, obj, _ := objects.GetConfigObjFromJsonData(nil, objHdl)
				currentIndex := int64(0)
				objCount := int64(MAX_COUNT_AUTO_DISCOVER_OBJ)
				resourceOwner := mgr.objectMgr.ObjHdlMap[resource].Owner
				err, _, _, _, objs = resourceOwner.GetBulkObject(obj, mgr.dbHdl.DBUtil,
					currentIndex, objCount)
				mgr.logger.Debug("AutoDiscover response: ", err, objs)
				if err == nil {
					for _, obj := range objs {
						objKey := mgr.dbHdl.GetKey(obj)
						_, err := mgr.dbHdl.GetObjectFromDb(obj, objKey)
						if err != nil {
							err = mgr.dbHdl.StoreObjectInDb(obj)
							if err != nil {
								mgr.logger.Err(fmt.Sprintln("Failed to store"+resource+" config in DB ", obj, err))
							} else {
								mgr.storeUUID(obj.GetKey())
								err = mgr.dbHdl.StoreObjectDefaultInDb(obj)
								if err != nil {
									mgr.logger.Err(fmt.Sprintln("Failed to store"+resource+" default config in DB ", obj, err))
								}
							}
						}
					}
				}
			}
		}
	}
}
