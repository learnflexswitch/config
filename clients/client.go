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
	"infra/sysd/sysdCommonDefs"
	"io/ioutil"
	"models/actions"
	"models/objects"
	"strconv"
	"time"
	"utils/dbutils"
	"utils/keepalive"
	"utils/logging"
)

type SystemStatusCB func() objects.SystemStatusState
type SystemSwVersionCB func() objects.SystemSwVersionState
type ExecuteConfigurationActionCB func(actions.ActionObj) error

type ClientMgr struct {
	logger                       *logging.Writer
	paramsDir                    string
	Clients                      map[string]ClientIf
	reconncetTimer               *time.Ticker
	SystemReady                  bool
	systemStatusCB               SystemStatusCB
	systemSwVersionCB            SystemSwVersionCB
	executeConfigurationActionCB ExecuteConfigurationActionCB
}

var gClientMgr *ClientMgr

type ClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

type DaemonJson struct {
	Name   string `json:"Name"`
	Enable bool   `json:"Enable"`
}

type DaemonsList struct {
	Daemons []DaemonJson `json:"Daemons"`
}

type ClientIf interface {
	Initialize(name string, address string)
	ConnectToServer() bool
	DisconnectFromServer() bool
	IsConnectedToServer() bool
	DisableServer() bool
	IsServerEnabled() bool
	CreateObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, bool)
	DeleteObject(obj objects.ConfigObj, objKey string, dbHdl *dbutils.DBUtil) (error, bool)
	GetBulkObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil, currMarker int64, count int64) (err error, objcount int64, nextMarker int64, more bool, objs []objects.ConfigObj)
	UpdateObject(dbObj objects.ConfigObj, obj objects.ConfigObj, attrSet []bool, op []objects.PatchOpInfo, objKey string, dbHdl *dbutils.DBUtil) (error, bool)
	GetObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, objects.ConfigObj)
	ExecuteAction(obj actions.ActionObj) error
	GetServerName() string
	PreUpdateValidation(dbObj, obj objects.ConfigObj, attrSet []bool, dbHdl *dbutils.DBUtil) error
	PostUpdateProcessing(dbObj, obj objects.ConfigObj, attrSet []bool, dbHdl *dbutils.DBUtil) error
	LockApiHandler()
	UnlockApiHandler()
}

func InitializeClientMgr(paramsDir string, logger *logging.Writer,
	systemStatusCB SystemStatusCB,
	systemSwVersionCB SystemSwVersionCB,
	executeConfigurationActionCB ExecuteConfigurationActionCB) *ClientMgr {
	mgr := new(ClientMgr)
	mgr.logger = logger
	mgr.paramsDir = paramsDir
	mgr.systemStatusCB = systemStatusCB
	mgr.systemSwVersionCB = systemSwVersionCB
	mgr.executeConfigurationActionCB = executeConfigurationActionCB
	clientsFile := paramsDir + "/clients.json"
	sysProfileFile := paramsDir + "/systemProfile.json"
	if rc := mgr.InitializeClientHandles(clientsFile, sysProfileFile); !rc {
		logger.Err("Error in initializing client handles")
		return nil
	}

	gClientMgr = mgr
	return mgr
}

//
//  This method reads the config file and connects to all the clients in the list
//
func (mgr *ClientMgr) InitializeClientHandles(clientsFile, sysProfileFile string) bool {
	var clientsList []ClientJson
	var daemonsList DaemonsList

	mgr.Clients = make(map[string]ClientIf)

	bytes, err := ioutil.ReadFile(clientsFile)
	if err != nil {
		mgr.logger.Err("Error in reading configuration file", clientsFile)
		return false
	}

	err = json.Unmarshal(bytes, &clientsList)
	if err != nil {
		mgr.logger.Err("Error in Unmarshalling Json")
		return false
	}
	for _, client := range clientsList {
		if ClientInterfaces[client.Name] != nil {
			mgr.Clients[client.Name] = ClientInterfaces[client.Name]
			mgr.Clients[client.Name].Initialize(client.Name, "localhost:"+strconv.Itoa(client.Port))
		}
	}

	bytes, err = ioutil.ReadFile(sysProfileFile)
	if err != nil {
		mgr.logger.Err("Failed to read systemProfile file")
		return false
	}
	err = json.Unmarshal(bytes, &daemonsList)
	if err != nil {
		mgr.logger.Err("Failed to unmarshal daemons enable list json")
		return false
	}
	for _, daemon := range daemonsList.Daemons {
		client, exist := mgr.Clients[daemon.Name]
		if exist {
			if daemon.Enable == false {
				client.DisableServer()
				mgr.logger.Info("Client", daemon.Name, "is disabled")
			}
		}
	}

	return true
}

func (mgr *ClientMgr) ListenToClientStateChanges() {
	clientStatusListener := keepalive.InitDaemonStatusListener()
	if clientStatusListener != nil {
		go clientStatusListener.StartDaemonStatusListner()
		for {
			select {
			case clientStatus := <-clientStatusListener.DaemonStatusCh:
				mgr.logger.Info("Received client status: ", clientStatus.Name, clientStatus.Status)
				if mgr.IsReady() {
					switch clientStatus.Status {
					case sysdCommonDefs.STOPPED, sysdCommonDefs.RESTARTING:
						mgr.DisconnectFromClient(clientStatus.Name)
					case sysdCommonDefs.UP:
						go mgr.ConnectToClient(clientStatus.Name)
					}
				}
			}
		}
	}
}

//
//  This method connects to all the config daemon's clients
//
func (mgr *ClientMgr) ConnectToAllClients(clientNameCh chan string) bool {
	mgr.reconncetTimer = time.NewTicker(time.Millisecond * 1000)
	mgr.SystemReady = false
	disabledClientsCount := 0
	for clientName, client := range mgr.Clients {
		if client.IsServerEnabled() {
			client.ConnectToServer()
			if client.IsConnectedToServer() {
				clientNameCh <- clientName
			}
		} else {
			disabledClientsCount++
		}
	}
	logCount := 0
	for t := range mgr.reconncetTimer.C {
		_ = t
		connectedClientsCount := 0
		for clientName, client := range mgr.Clients {
			if client.IsServerEnabled() {
				if client.IsConnectedToServer() == false {
					if logCount%60 == 0 {
						mgr.logger.Info("Trying to connect to ", clientName)
					}
					client.ConnectToServer()
					if client.IsConnectedToServer() {
						clientNameCh <- clientName
						connectedClientsCount++
					}
				} else {
					connectedClientsCount++
				}
			}
		}
		logCount++

		if len(mgr.Clients) == (disabledClientsCount + connectedClientsCount) {
			mgr.reconncetTimer.Stop()
			break
		}
	}
	mgr.logger.Info("Connected to all clients")
	clientNameCh <- "Client_Init_Done"
	return true
}

//
// This method is to disconnect from all clients
//
func (mgr *ClientMgr) DisconnectFromAllClients() bool {
	for _, client := range mgr.Clients {
		if client.IsConnectedToServer() {
			client.DisconnectFromServer()
		}
	}
	return true
}

//
// This method is to check if config manager is ready to accept config requests
//
func (mgr *ClientMgr) IsReady() bool {
	return mgr.SystemReady
}

func (mgr *ClientMgr) GetUnconnectedClients() []string {
	unconnectedClients := make([]string, 0)
	for clntName, client := range mgr.Clients {
		if client.IsServerEnabled() && client.IsConnectedToServer() == false {
			unconnectedClients = append(unconnectedClients, clntName)
		}
	}
	return unconnectedClients
}

func (mgr *ClientMgr) DisconnectFromClient(name string) error {
	client, exist := mgr.Clients[name]
	if exist {
		if client.IsConnectedToServer() {
			client.DisconnectFromServer()
		}
	}
	return nil
}

func (mgr *ClientMgr) ConnectToClient(name string) error {
	client, exist := mgr.Clients[name]
	waitCount := 0
	if exist {
		if client.IsServerEnabled() && !client.IsConnectedToServer() {
			reconncetTimer := time.NewTicker(time.Millisecond * 1000)
			for t := range reconncetTimer.C {
				_ = t
				waitCount++
				if waitCount%10 == 0 {
					mgr.logger.Info("Connecting to client ", name)
				}
				if !client.IsConnectedToServer() {
					client.ConnectToServer()
				} else {
					reconncetTimer.Stop()
					break
				}
			}
		}
	}
	return nil
}
