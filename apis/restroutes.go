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

package apis

import (
	"config/actions"
	"config/clients"
	"config/objects"
	"github.com/gorilla/mux"
	"models/events"
	modelObjs "models/objects"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"utils/logging"
	"utils/ringBuffer"
)

type ApiRoute struct {
	Name        string           // Unique Identifier to identify this route
	Method      string           // REST Method POST/GET/PATCH....
	Pattern     string           // Endpoint URI
	HandlerFunc http.HandlerFunc // Function reposnsible for executing the request
}

type ApiRoutes []ApiRoute

type ApiMgr struct {
	logger        *logging.Writer
	clientMgr     *clients.ClientMgr
	objectMgr     *objects.ObjectMgr
	actionMgr     *actions.ActionMgr
	dbHdl         *objects.DbHandler
	apiVer        string
	apiBase       string
	apiBaseConfig string
	apiBaseState  string
	apiBaseAction string
	apiBaseEvent  string
	basePath      string
	fullPath      string
	pRestRtr      *mux.Router
	restRoutes    []ApiRoute
	apiCallSeqNum uint32
	apiLogRB      *ringBuffer.RingBuffer
	ApiCallStats  ApiCallStats
}

var gApiMgr *ApiMgr

type ApiCallStats struct {
	NumCreateCalls        int32
	NumCreateCallsSuccess int32
	NumDeleteCalls        int32
	NumDeleteCallsSuccess int32
	NumUpdateCalls        int32
	NumUpdateCallsSuccess int32
	NumGetCalls           int32
	NumGetCallsSuccess    int32
	NumActionCalls        int32
	NumActionCallsSuccess int32
}

func InitializeApiMgr(paramsDir string, logger *logging.Writer, dbHdl *objects.DbHandler, clientMgr *clients.ClientMgr, objectMgr *objects.ObjectMgr, actionMgr *actions.ActionMgr) *ApiMgr {
	var err error
	mgr := new(ApiMgr)
	mgr.logger = logger
	mgr.dbHdl = dbHdl
	mgr.clientMgr = clientMgr
	mgr.objectMgr = objectMgr
	mgr.actionMgr = actionMgr
	mgr.apiVer = "v1"
	mgr.apiBase = "/public/" + mgr.apiVer + "/"
	mgr.apiBaseConfig = mgr.apiBase + "config/"
	mgr.apiBaseState = mgr.apiBase + "state/"
	mgr.apiBaseAction = mgr.apiBase + "action/"
	mgr.apiBaseEvent = mgr.apiBase + "event/"
	if mgr.fullPath, err = filepath.Abs(paramsDir); err != nil {
		logger.Err("Unable to get absolute path for " + paramsDir + " Error: " + err.Error())
		return nil
	}
	mgr.basePath, _ = filepath.Split(mgr.fullPath)
	mgr.apiCallSeqNum = 0
	mgr.apiLogRB = new(ringBuffer.RingBuffer)
	mgr.apiLogRB.SetRingBufferCapacity(1024)
	mgr.ReadApiCallInfoFromDb()
	gApiMgr = mgr
	return mgr
}

func (mgr *ApiMgr) InitializeActionRestRoutes() bool {
	var rt ApiRoute
	actionList := mgr.actionMgr.GetAllActions()
	for _, action := range actionList {
		rt = ApiRoute{action + "action",
			"POST",
			mgr.apiBaseAction + "{rest:[a-zA-Z0-9]+}",
			HandleRestRouteAction,
		}
		mgr.restRoutes = append(mgr.restRoutes, rt)
	}
	return true
}

func (mgr *ApiMgr) InitializeEventRestRoutes() bool {
	var rt ApiRoute
	for key, _ := range events.EventObjectMap {
		rt = ApiRoute{key + "events",
			"GET",
			mgr.apiBaseEvent + "{rest:[a-zA-Z0-9]+}",
			HandleRestRouteEvent,
		}
		mgr.restRoutes = append(mgr.restRoutes, rt)
	}
	return true
}

//
//  This method reads the model data and creates rest route interfaces.
//
func (mgr *ApiMgr) InitializeRestRoutes() bool {
	var rt ApiRoute
	rt = ApiRoute{"create",
		"POST",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteCreate,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"deletebyid",
		"DELETE",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}" + "/" + "{objId}",
		HandleRestRouteDeleteForId,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"deletebykey",
		"DELETE",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteDelete,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"updatebyid",
		"PATCH",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}" + "/" + "{objId}",
		HandleRestRouteUpdateForId,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"updatebykey",
		"PATCH",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteUpdate,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"getbyid",
		"GET",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}" + "/" + "{objId}",
		HandleRestRouteGetConfigForId,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"getbykeyorbulk",
		"GET",
		mgr.apiBaseConfig + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteGetConfig,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"showbyid",
		"GET",
		mgr.apiBaseState + "{rest:[a-zA-Z0-9]+}" + "/" + "{objId}",
		HandleRestRouteGetStateForId,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"showbykeyorbulk",
		"GET",
		mgr.apiBaseState + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteGetState,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	rt = ApiRoute{"showbykeyorbulk",
		"POST",
		mgr.apiBaseState + "{rest:[a-zA-Z0-9]+}",
		HandleRestRouteGetState,
	}
	mgr.restRoutes = append(mgr.restRoutes, rt)
	return true
}

func HandleRestRouteCreate(w http.ResponseWriter, r *http.Request) {
	ConfigObjectCreate(w, r)
	return
}

func HandleRestRouteDeleteForId(w http.ResponseWriter, r *http.Request) {
	ConfigObjectDeleteForId(w, r)
	return
}

func HandleRestRouteDelete(w http.ResponseWriter, r *http.Request) {
	ConfigObjectDelete(w, r)
	return
}

func HandleRestRouteUpdateForId(w http.ResponseWriter, r *http.Request) {
	ConfigObjectUpdateForId(w, r)
	return
}

func HandleRestRouteUpdate(w http.ResponseWriter, r *http.Request) {
	ConfigObjectUpdate(w, r)
	return
}

func HandleRestRouteGetConfigForId(w http.ResponseWriter, r *http.Request) {
	GetOneConfigObjectForId(w, r)
	return
}

func HandleRestRouteGetConfig(w http.ResponseWriter, r *http.Request) {
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.Split(resource, "?")[0]
	resource = strings.ToLower(resource)
	_, ok := modelObjs.ConfigObjectMap[resource]
	if ok {
		GetOneConfigObject(w, r)
	} else {
		_, ok := modelObjs.ConfigObjectMap[resource[:len(resource)-1]]
		if ok {
			BulkGetConfigObjects(w, r)
		} else {
			RespondErrorForApiCall(w, SRNotFound, "")
		}
	}
	return
}

func HandleRestRouteGetStateForId(w http.ResponseWriter, r *http.Request) {
	GetOneStateObjectForId(w, r)
	return
}

func HandleRestRouteGetState(w http.ResponseWriter, r *http.Request) {
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseState), "/")[0]
	resource = strings.Split(resource, "?")[0]
	resource = strings.ToLower(resource)
	_, ok := modelObjs.ConfigObjectMap[resource+"state"]
	if ok {
		GetOneStateObject(w, r)
	} else {
		_, ok := modelObjs.ConfigObjectMap[resource[:len(resource)-1]+"state"]
		if ok {
			BulkGetStateObjects(w, r)
		} else {
			RespondErrorForApiCall(w, SRNotFound, "")
		}
	}
	return
}

func HandleRestRouteBulkGetConfig(w http.ResponseWriter, r *http.Request) {
	BulkGetConfigObjects(w, r)
	return
}

func HandleRestRouteBulkGetState(w http.ResponseWriter, r *http.Request) {
	BulkGetStateObjects(w, r)
	return
}

func HandleRestRouteAction(w http.ResponseWriter, r *http.Request) {
	ExecuteActionObject(w, r)
	return
}

func HandleRestRouteEvent(w http.ResponseWriter, r *http.Request) {
	EventObjectGet(w, r)
	return
}

func (mgr *ApiMgr) ReadApiCallInfoFromDb() error {
	apiInfo := modelObjs.ConfigLogState{}
	apiInfos, err := mgr.dbHdl.GetAllObjFromDb(apiInfo)
	if err == nil {
		for _, apiInfo := range apiInfos {
			mgr.apiCallSeqNum++
			mgr.apiLogRB.InsertIntoRingBuffer(apiInfo)
		}
	}
	return nil
}

func (mgr *ApiMgr) StoreApiCallInfo(r *http.Request, api, operation string, body []byte, errCode int, errStr string) error {
	var result string
	var data string
	mgr.apiCallSeqNum++
	if errCode == SRSuccess {
		result = "Success"
	} else {
		result = errStr
	}
	data = strings.Replace(string(body), "\\", "", -1)
	data = strings.Replace(data, "\"", "", -1)
	apiInfo := modelObjs.ConfigLogState{
		SeqNum:    mgr.apiCallSeqNum,
		API:       api,
		Time:      time.Now().String(),
		Operation: operation,
		Data:      data,
		Result:    result,
		UserAddr:  r.RemoteAddr,
		UserName:  "", // confd does not know username information
	}
	err := mgr.dbHdl.StoreObjectInDb(apiInfo)
	if err != nil {
		mgr.logger.Info("Failed to store ApiCall information.", err)
		return err
	} else {
		_, oldApiInfo := mgr.apiLogRB.InsertIntoRingBuffer(apiInfo)
		if oldApiInfo != nil {
			err = mgr.dbHdl.DeleteObjectFromDb(apiInfo)
			if err != nil {
				mgr.logger.Info("Failed to delete old ApiCall information.", err)
			}
		}
	}
	return nil
}

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		inner.ServeHTTP(w, r)
		gApiMgr.logger.Debug("%s\t%s\t%s\n", r.Method, r.RequestURI, time.Since(start))
	})
}

//
//  This method creates new rest router interface
//
func (mgr *ApiMgr) InstantiateRestRtr() *mux.Router {
	mgr.pRestRtr = mux.NewRouter().StrictSlash(true)
	mgr.pRestRtr.PathPrefix("/api-docs/").Handler(http.StripPrefix("/api-docs/",
		http.FileServer(http.Dir(mgr.fullPath+"/docsui"))))

	for _, route := range mgr.restRoutes {
		var handler http.Handler
		handler = Logger(route.HandlerFunc, route.Name)
		mgr.pRestRtr.Methods(route.Method).Path(route.Pattern).Handler(handler)
	}
	mgr.pRestRtr.PathPrefix("rest:/[a-zA-Z0-9]+").Handler(http.StripPrefix("rest:/[a-zA-Z0-9]+", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	mgr.pRestRtr.PathPrefix("/settings/").Handler(http.StripPrefix("/settings/", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	mgr.pRestRtr.PathPrefix("/performance/").Handler(http.StripPrefix("/performance/", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	mgr.pRestRtr.PathPrefix("/alarms/").Handler(http.StripPrefix("/alarms/", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	mgr.pRestRtr.PathPrefix("/logs/").Handler(http.StripPrefix("/logs/", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	mgr.pRestRtr.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(mgr.fullPath+"/flexui"))))
	return mgr.pRestRtr
}

func (mgr *ApiMgr) GetRestRtr() *mux.Router {
	return mgr.pRestRtr
}
