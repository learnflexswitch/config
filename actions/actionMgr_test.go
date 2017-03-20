package actions

import (
	"bytes"
	"config/clients"
	"config/objects"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	modelActions "models/actions"
	modelObjs "models/objects"
	"net/http"
	"os"
	"testing"
	"time"
	"utils/logging"
)

//usage: go test or
//       go test -params=<paramsDir> e,g: go test -params=/opt/flexswitch/params/

var paramsDir = flag.String("params", "../../models/actions", "Location of actionJsonFile")
var Logger *logging.Writer
var infoListFile []string
var actionMgr *ActionMgr
var dbHdl *objects.DbHandler

func GetSystemStatus() modelObjs.SystemStatusState {
	systemStatus := modelObjs.SystemStatusState{}
	systemStatus.Name, _ = os.Hostname()
	systemStatus.Ready = true
	systemStatus.Reason = "None"
	systemStatus.UpTime = time.Now().String()

	// Read DaemonStates from db
	var daemonState modelObjs.DaemonState
	daemonStates, _ := daemonState.GetAllObjFromDb(dbHdl)
	systemStatus.FlexDaemons = make([]modelObjs.DaemonState, len(daemonStates))
	for idx, daemonState := range daemonStates {
		systemStatus.FlexDaemons[idx] = daemonState.(modelObjs.DaemonState)
	}
	return systemStatus
}

func GetSystemSwVersion() modelObjs.SystemSwVersionState {
	systemSwVersion := modelObjs.SystemSwVersionState{}
	return systemSwVersion
}

func Init() {
	fmt.Println("ActionMgr: Start logger")
	logger, err := logging.NewLogger("actionMgr", "ActionMgr", true)
	if err != nil {
		fmt.Println("Failed to start logger. Nothing will be logged ...")
	}
	Logger = logger
	paramsDirName := *paramsDir
	fmt.Println("paramsDirName:", paramsDirName)
	actionConfigFiles := [...]string{paramsDirName + "/genActionConfig.json"}
	infoListFile = make([]string, 0)
	infoListFile = actionConfigFiles[:]
}
func TestInit(t *testing.T) {
	Init()
	dbHdl = objects.InstantiateDbIf(Logger)
	clientMgr := clients.InitializeClientMgr(".././params/clients.json", Logger, GetSystemStatus, GetSystemSwVersion)
	objects.CreateObjectMap()
	objectConfigFiles := [...]string{"../../models/objects/genObjectConfig.json"}
	o := objects.InitializeObjectMgr(objectConfigFiles[:], Logger, clientMgr)
	v := InitializeActionMgr(*paramsDir, infoListFile, Logger, dbHdl, o, clientMgr)
	if v == nil {
		fmt.Println("actionMgr nil, not successfully initialized")
	} else {
		fmt.Println("ActionMgr Initialized")
	}
	t.Log("For ", infoListFile, " nil, nil",
		"got", v)
	actionMgr = v
}
func TestInitializeActionObjectHandles(*testing.T) {
	fmt.Println("****TestInitializeActionHandles****")
	var init bool
	init = actionMgr.InitializeActionObjectHandles(infoListFile)
	fmt.Println("init status with infoListFile:", infoListFile, " is:", init)
	init = actionMgr.InitializeActionObjectHandles(make([]string, 0))
	fmt.Println("init status with empty infoListFile:", init)
	fmt.Println("*************************")
}

func TestGetAllActions(t *testing.T) {
	fmt.Println("****TestGetAllActions****")
	actions := actionMgr.GetAllActions()
	fmt.Println("actions:", actions)
	fmt.Println("*************************")
}
func _getActionObj(resource string, r *http.Request) (actionObj modelActions.ActionObj, err error) {
	if actionobjHdl, ok := modelActions.ActionMap["ApplyConfig"]; ok {
		if _, actionObj, err = GetActionObj(r, actionobjHdl); err == nil {
			return actionObj, err
		} else {
			fmt.Println("Error:", err, " error getting action obj")
			return actionObj, err
		}
	} else {
		fmt.Println("actionMap returned nil")
		return actionObj, errors.New("nil objHdl")
	}
	return actionObj, err
}
func TestGetActionObj(t *testing.T) {
	fmt.Println("**** Test Get Action obj **** ")
	var r *http.Request
	if actionobjHdl, ok := modelActions.ActionMap["ApplyConfig"]; ok {
		if _, _, err := GetActionObj(r, actionobjHdl); err == nil {
			if err != nil {
				fmt.Println("Error:", err, " error getting action obj")
			}
		}
	}
	if actionobjHdl, ok := modelActions.ActionMap["ApplConfig"]; ok {
		if _, _, err := GetActionObj(r, actionobjHdl); err == nil {
			if err != nil {
				fmt.Println("Error:", err, " error getting action obj")
			}
		}
	}
	fmt.Println("*************************")
}

func TestCreateConfig(t *testing.T) {
	fmt.Println("****TestCreateConfig****")
	body := "{\"Name\": \"lo1\",\"Type\": \"Loopback\" }"
	CreateConfig("LogicalIntf", json.RawMessage(body))
	fmt.Println("Created object 1")
	CreateConfig("LogicalInt", json.RawMessage(""))
	fmt.Println("Created object 2")
	CreateConfig("LogicalIntf", json.RawMessage(""))
	fmt.Println("Created object 3")
	fmt.Println("*************************")
}

func TestUpdateConfig(t *testing.T) {
	fmt.Println("****TestUpdateConfig****")
	body := "{\"Name\": \"lo1\",\"Type\": \"Loopback\" }"
	UpdateConfig("LogicalIntf", json.RawMessage(body))
	fmt.Println("Updated object 1")
	UpdateConfig("LogicalInt", json.RawMessage(""))
	fmt.Println("Updated object 2")
	UpdateConfig("LogicalIntf", json.RawMessage(""))
	fmt.Println("Updated object 3")
	fmt.Println("*************************")
}

func TestApplyAction(t *testing.T) {
	fmt.Println("****TestApplyAction****")
	for _, applyResource := range ApplyConfigOrder {
		ApplyConfigObject(modelActions.ApplyConfig{}, applyResource)
	}
	ApplyConfigObject(modelActions.ApplyConfig{}, "LogicalInt")
	fmt.Println("*************************")
}

func TestOpenFile(t *testing.T) {
	fmt.Println("**** TestOpenFile **** ")
	OpenFile("testCfg1.json")
	OpenFile("test.txt")
	fmt.Println("*************************")
}
func TestSaveAction(t *testing.T) {
	fmt.Println("****TestSaveAction****")
	var wdata modelActions.SaveConfigObj
	wdata.ConfigData = make(map[string][]interface{})
	for _, applyResource := range ApplyConfigOrder {
		SaveConfigObject(wdata, applyResource)
	}
	fmt.Println("*************************")
}

func TestResetAction(t *testing.T) {
	fmt.Println("****TestResetAction****")
	ResetConfigObject(modelActions.ResetConfig{})
	fmt.Println("*************************")
}

func TestExecuteApplyActionObj(t *testing.T) {
	fmt.Println("**** Test ApplyConfig action **** ")
	objFile := "testCfg1.json"
	body, err := ioutil.ReadFile(objFile)
	if err != nil {
		fmt.Println("Error in reading Action configuration file", objFile)
		return
	}
	var r *http.Request
	r, err = http.NewRequest("POST", "http://localhost:8080/public/v1/action/ApplyConfig", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Error getting new http request, err:", err)
		return
	}
	r.Header.Set("Content-Type", "application/json")
	if actionobjHdl, ok := modelActions.ActionMap["ApplyConfig"]; ok {
		if _, actionobj, err := GetActionObj(r, actionobjHdl); err == nil {
			err = ExecutePerformAction(actionobj)
			if err != nil {
				fmt.Println("Error:", err, " executing apply config ation")
			}
		}
	}
	fmt.Println("*************************")
}

func TestExecuteSaveActionObj(t *testing.T) {
	fmt.Println("****Test SaveConfig Action****")
	var r *http.Request
	var body []byte
	r, err := http.NewRequest("POST", "http://localhost:8080/public/v1/action/SaveConfig", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Error getting new http request, err:", err)
		return
	}
	r.Header.Set("Content-Type", "application/json")
	if actionobjHdl, ok := modelActions.ActionMap["SaveConfig"]; ok {
		if _, actionobj, err := GetActionObj(r, actionobjHdl); err == nil {
			err = ExecutePerformAction(actionobj)
			if err != nil {
				fmt.Println("Error:", err, " executing save config ation")
			}
		}
	}
	fmt.Println("*************************")
}

func TestExecuteResetActionObj(t *testing.T) {
	fmt.Println("****Test ResetConfig Action****")
	var r *http.Request
	var body []byte
	r, err := http.NewRequest("POST", "http://localhost:8080/public/v1/action/ResetConfig", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Error getting new http request, err:", err)
		return
	}
	r.Header.Set("Content-Type", "application/json")
	if actionobjHdl, ok := modelActions.ActionMap["ResetConfig"]; ok {
		if _, actionobj, err := GetActionObj(r, actionobjHdl); err == nil {
			err = ExecutePerformAction(actionobj)
			if err != nil {
				fmt.Println("Error:", err, " executing reset config ation")
			}
		}
	}
	fmt.Println("*************************")
}
