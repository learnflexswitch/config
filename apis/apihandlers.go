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
	"config/objects"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	modelActions "models/actions"
	modelEvents "models/events"
	modelObjs "models/objects"
	"net/http"
	"reflect"
	"strconv"
	"strings"
        "os"
        "io"
        "io/ioutil"
	"utils/eventUtils"
        "net/http/httputil"
        "bytes"
	//"utils/dbutils"
	//"net/url"
	//"path"
)

const (
	MAX_OBJECTS_IN_GETBULK = 1024
)

type baseResponse struct {
	AccessControlAllowOrigin  string `json:"Access-Control-Allow-Origin"`
	AccessControlAllowHeaders string `json:"Access-Control-Allow-Headers"`
	AccessControlAllowMethods string `json:"Access-Control-Allow-Methods"`
	AccessControlMaxAge       string `json:"Access-Control-Max_age"`
}

type ConfigResponse struct {
	baseResponse
	UUId   string `json:"ObjectId"`
	Result string `json:"Result"`
}

type ReturnObject struct {
	ObjectId            string `json:"ObjectId"`
	modelObjs.ConfigObj `json:"Object"`
}

type GetBulkResponse struct {
	MoreExist     bool  `json:"MoreExist"`
	ObjCount      int64 `json:"ObjCount"`
	CurrentMarker int64 `json:"CurrentMarker"`
	NextMarker    int64 `json:"NextMarker"`
	Objects       []ReturnObject
}

type GetEventResponse struct {
	Objects []modelEvents.EventObj
}

type ActionResponse struct {
	Result string `json:"Result"`
}

type ErrorResponse struct {
	Result string `json:"Result"`
}

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
	SRValidationFailed  = 16
	SRUnmarshalError    = 17
	SRPatchDecodeError  = 18
)

type RuleFile struct {
  Name   string `DESCRIPTION: "Name of the rule file"`
  Path   string `DESCRIPTION: "Path of rule file"`
  Rules  [] string `DESCRIPTION: "Rules "`
}

// SR error strings
var ErrString = map[int]string{
	SRFail:              "Configuration failed.",
	SRSuccess:           "Success",
	SRSystemNotReady:    "System not ready.",
	SRRespMarshalErr:    "Configuration applied successfully. However, failed to marshal response.",
	SRNotFound:          "Failed to find entry.",
	SRIdStoreFail:       "Failed to store Id in DB. However, configuration has been applied.",
	SRIdDeleteFail:      "Failed to delete Id from DB. However, configuration has been removed.",
	SRServerError:       "Backend server failed to apply configuration.",
	SRObjHdlError:       "Failed to get object handle.",
	SRObjMapError:       "Failed to get object map.",
	SRBulkGetTooLarge:   "More than maximum number of objects requested in a bulkget.",
	SRNoContent:         "Insufficient information.",
	SRAuthFailed:        "User authentication failed.",
	SRAlreadyConfigured: "Already configured. Delete and Update operations are allowed.",
	SRUpdateKeyError:    "Cannot update key in an object.",
	SRUpdateNoChange:    "Nothing to be updated.",
	SRValidationFailed:  "Config validation failed.",
	SRUnmarshalError:    "Unmarshal of json data failed.",
	SRPatchDecodeError:  "Failed to decode patch data.",
}

//Added for Dpi-Start
func listAllFiles(path string) []string {

    fileList := []string{}
    files, err := ioutil.ReadDir(path)
    if err != nil {
       fmt.Println(err)
    }
    for _, file := range files {
        fileList =append( fileList, file.Name())
    }
    return fileList
}

func listAllRules(filename string) [] string {
   content, err := ioutil.ReadFile(filename)
   if err != nil {
      fmt.Println(err)
      return nil
   }
   lines := strings.Split(string(content), "\n")
   return lines

}

func escapeCtrl(json string) string {
  ret := json
  ret = strings.Replace(ret,"{","\\{",-1)
  ret = strings.Replace(ret,"}","\\}",-1)
  ret = strings.Replace(ret,"\\","\\\\",-1)
  ret = strings.Replace(ret,"\"","\\\"",-1)
  return ret
}

func addRule(file string, rule string) error {
      f, err :=  os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660);
      if err != nil {
         fmt.Fprintln(os.Stderr, err)
         return err
      }
      defer f.Close()

      _, err = f.WriteString(rule + "\n")
      if err != nil {
          fmt.Print(os.Stderr,err)
          return err
      }
      return nil
}

func exists(rule string, rules [] string) bool {
   if rules == nil {
      return false
   }
   for _, myrule := range rules {
     if strings.Trim(myrule," ") == strings.Trim(rule," ") {
        return true;
     }
   }
   return false
}



func delRule(file string, rule string) error {

      content, err := ioutil.ReadFile(file)

      f, err :=  os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0660);
      if err != nil {
         fmt.Fprintln(os.Stderr, err)
         return err
      }
      defer f.Close()
      lines := strings.Split(string(content), "\n")
      for  _, wkrule := range  lines {
          if strings.Trim(wkrule, " ") == strings.Trim(rule," ") {
             wkrule = "#"+ wkrule
         }
         _, err = f.WriteString(wkrule + "\n")
         if err != nil {
            fmt.Print(os.Stderr,err)
            return err
         }
      }
      return nil
}

func updateRule(file string, rule string) error {
      content, err := ioutil.ReadFile(file)
      if rule == "" {
        fmt.Println("No rules needed")
        return nil
      }

      f, err :=  os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0660);
      if err != nil {
         fmt.Fprintln(os.Stderr, err)
         return err
      }
      defer f.Close()
      exist := 0
      lines := strings.Split(string(content), "\n")
      for  _, wkrule := range  lines {
         //fmt.Print(wkrule)
         if strings.Trim(wkrule, " ") == strings.Trim(rule," ") {
            exist =1
         }
         fmt.Print("Wrigint ..." + wkrule)
         _, err = f.WriteString(wkrule + "\n")
         if err != nil {
             fmt.Print(os.Stderr,err)
             return err
         }

      }
      if exist == 0 && rule != "" {
          f.WriteString(rule + "\n")
      }
      return nil
}


func delRules(ruleFile RuleFile) string {
  path := "/etc/snort/rules/"
  name := ruleFile.Name
  filename :=path +name

  delRules := ruleFile.Rules
  for  _, delRuls := range delRules {
     delRule(filename,delRuls)
  }
  return ""

}

func updateRules(ruleFile RuleFile) string {
  path := "/etc/snort/rules/"
  name := ruleFile.Name
  filename :=path + name
  //fmt.Println(filename)

  rules := ruleFile.Rules

  if len(rules) == 0 {
     //err := os.Rename(filename , filename + ".bak")
     //if err != nil {
     //   fmt.Println(err)
     //}
     //fmt.Println("Rules is 0")
     return ""
  }

  for  _, rule := range rules {
     //fmt.Println(rule.Rule)
     //fmt.Println("updateRule " + filename + ".." + rule + "\n")
     updateRule(filename,rule)
  }
  return ""

}

/*
func dpiMarshalFile(file string) string {
   path := "/etc/snort/rules/"
   json := ""
   head := "{\"Object\": { \"name\":\"" + file + "\",\"Path\":\"" + path + "\",\"Rules\":["
   rules := listAllRules(path + file)
   rulejson := ""
   for _, rule := range rules {
      wkrule :=rule
      wkrule = strings.Trim(wkrule," ")
      if  wkrule != "" && !strings.HasPrefix(wkrule, "#")  {
         rule = escapeCtrl(rule)
         if rulejson == "" {
            rulejson = "{\"Rule\":\"" + rule + "\"}"
         }else {
            rulejson = rulejson + ",{\"Rule\":\"" + rule + "\"}"
         }
     }
   }
   rulejson = rulejson + "]}"
   json = head + rulejson + ",\"ObjectId\":\"" + file + "\"}"
   return json
}
*/

func dpiMarshalFile(file string) string {
   path := "/etc/snort/rules/"
   json := ""
   head := "{\"Object\": { \"name\":\"" + file + "\",\"Path\":\"" + path + "\",\"Rules\":["
   rules := listAllRules(path + file)
   rulejson := ""
   for _, rule := range rules {
      wkrule :=rule
      wkrule = strings.Trim(wkrule," ")
      if  wkrule != "" && !strings.HasPrefix(wkrule, "#")  {
         rule = escapeCtrl(rule)
         if rulejson == "" {
            rulejson = "\"" + rule + "\""
         }else {
            rulejson = rulejson + ",\"" + rule + "\""
         }
     }
   }
   rulejson = rulejson + "]}"
   json = head + rulejson + ",\"ObjectId\":\"" + file + "\"}"
   return json
}


func dpiMarshal(objId string) string {
   path := "/etc/snort/rules/"
   json := "{\"CurrentMarker\":0,\"MoreExist\":false,\"NextMarker\":0,\"ObjCount\":"
   mylog("YORK, dpiMarshal ,objId=" + objId)
   if objId != "" {
      return dpiMarshalFile(objId)
   }
   
   mylog("YORK, dpiMarshal ,objId2=" + objId)
   files := listAllFiles(path)
   json = json + strconv.Itoa(len(files))  + ",\"Objects\":["
   wkjson :=""
   for _, file := range files {
     if wkjson == "" {
        wkjson = dpiMarshalFile(file)
     } else {
        wkjson = wkjson + "," + dpiMarshalFile(file)
     }
  }
  json = json + wkjson + "]}"

  return json
}

//Added for Dpi-end


//Given a code reurn error string
func SRErrString(errCode int) string {
	return "Error: " + ErrString[errCode]
}

func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	//if err := json.NewEncoder(w).Encode(peers); err != nil {
	//	return
	//}
}

func (resp *ConfigResponse) FillBaseConfigResponse() {
	resp.AccessControlAllowOrigin = "*"
	resp.AccessControlAllowHeaders = "Origin, X-Requested-With, Content-Type, Accept"
	resp.AccessControlAllowMethods = "POST, GET, OPTIONS, PATCH, DELETE"
	resp.AccessControlMaxAge = "86400"
}

func RespondErrorForApiCall(w http.ResponseWriter, errCode int, errString string) error {
	var errResp ErrorResponse
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if errCode == SRBulkGetTooLarge {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	} else if errCode == SRSystemNotReady {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
	errResp.Result = SRErrString(errCode) + " " + errString
	js, _ := json.Marshal(errResp)
	w.Write(js)
	return nil
}

func ReplaceMultipleSeperatorInUrl(urlStr string) string {
	var retStr string
	strs := strings.Split(urlStr, "/")
	for i := 0; i < len(strs); i++ {
		if len(strs[i]) > 0 {
			retStr = retStr + "/" + strs[i]
		}
	}
	return retStr
}

func GetOneConfigObjectForId(w http.ResponseWriter, r *http.Request) {
	var obj modelObjs.ConfigObj
	var dbObj modelObjs.ConfigObj
	var objKey string
	var retObj ReturnObject
	var err error

	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.ToLower(resource)

        if resource == "dpirules" {
            objHdl, ok := modelObjs.ConfigObjectMap[resource]
            if !ok {
                mylog("YORK, GetOneConfigObjectForId modelObjs.ConfigObjectMap error")
            } else {
                mylog("YORK, GetOneConfigObjectForId modelObjs.ConfigObjectMap OK")
                 _, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
                if err != nil {
                    mylog("YORK, GetOneConfigObjectForId  bjects.GetConfigObjFromJsonData error")
                    body, err := ioutil.ReadAll(r.Body)
                    if err != nil {
                          mylog("YORK, GetOneConfigObjectForId , r.Body=")
                    }else{
                          mylog("YORK, GetOneConfigObjectForId , body=" + bytes.NewBuffer(body).String())
                          
                    }
                }else {
                     mylog("YORK, GetOneConfigObjectForId  bjects.GetConfigObjFromJsonData OK")
                }
            }
            vars := mux.Vars(r)
            objId := vars["objId"]
             
            key := vars["key"]
        
            mylog("YORK, GetOneConfigObjectForId  objId=" + objId)
            mylog("YORK, GetOneConfigObjectForId  key=" + key)
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(objId)
            w.Write([]byte(js))
            mylog("YORK, GetOneConfigObjectForId  js=" + js)
 
         return

        }

	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	_, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	vars := mux.Vars(r)
	uuid := vars["objId"]
	//if objId is provided then read objkey from DB
	objKey, err = gApiMgr.dbHdl.GetObjKeyFromUUID(uuid)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	dbObj, err = gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	} else {
		retObj.ConfigObj = dbObj
	}
	retObj.ObjectId = uuid
	js, err := json.Marshal(retObj)
	if err == nil {
		gApiMgr.ApiCallStats.NumGetCallsSuccess++
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
	return
}

func GetOneConfigObject(w http.ResponseWriter, r *http.Request) {
	var obj modelObjs.ConfigObj
	var objKey string
	var retObj ReturnObject
	var err error
	var uuid string

	resource := ""
	queryData := ""
	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource = strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.Split(resource, "?")[0]
	resource = strings.ToLower(resource)
            
        mylog("YORK, GetOneConfigObject, resource=" + resource+ ";urlStr=" + urlStr)
        queryDataList := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "?")
        if len(queryDataList) > 1 {
                queryData = queryDataList[1]
        }
        mylog("YORK, GetOneConfigObject,queryData=" + queryData)
       
        dump, err := httputil.DumpRequestOut(r, true) 
        if err == nil {
           mylog("YORK, GetOneConfigObject, httputil.DumpRequestOut error," )
        }else {
            mylog("YORK, GetOneConfigObject, http.Request=" + bytes.NewBuffer(dump).String())
        }

        if resource == "dpirules" {
           objHdl, ok := modelObjs.ConfigObjectMap[resource]
           if objHdl != nil {
                mylog("YORK, GetOneConfigObject modelObjs.ConfigObjectMap objHdlOK")
           }

           if !ok {
               mylog("YORK, GetOneConfigObject modelObjs.ConfigObjectMap error")
           }else {
                mylog("YORK, GetOneConfigObject modelObjs.ConfigObjectMap OK")
           }
            
           name := ""
           path :=""
   
           if queryData == "" {
                 body, err := ioutil.ReadAll(io.LimitReader(r.Body, 4096))
                  if err != nil {
                     mylog("YORK, GetOneConfigObject ,err TRUE")
                  }

                 bodys := bytes.NewBuffer(body).String()
                 if bodys != "" {
                    var file RuleFile
                    err := json.Unmarshal(body, &file)
                    if err != nil {
                       mylog("YORK, GetOneConfigObject , json.Unmarshal error" )
                    }else{
                       name = file.Name
                       path = file.Path
                       mylog("YORK, GetOneConfigObject , json.Unmarshal OK" )
                    }
                    mylog("YORK, GetOneConfigObject , name=" + name)
                    mylog("YORK, GetOneConfigObject , path=" + path)
                       
                 }
           }
           
           gApiMgr.ApiCallStats.NumGetCallsSuccess++
           w.Header().Set("Content-Type", "application/json; charset=UTF-8")
           w.WriteHeader(http.StatusOK)
           js := dpiMarshal(name)
           w.Write([]byte(js))
           mylog("YORK, GetOneConfigObject js=" + js)
           return

        }


	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	if queryData == "" {
		_, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
	} else {
		_, obj, err = objects.GetConfigObjFromQueryData(r, objHdl)
	}
	if err != nil || obj == nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	//Get key fields provided in the request.
	objKey = gApiMgr.dbHdl.GetKey(obj)
	retObj.ConfigObj, err = gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	uuid, err = gApiMgr.dbHdl.GetUUIDFromObjKey(objKey)
	retObj.ObjectId = uuid
	js, err := json.Marshal(retObj)
	if err == nil {
		gApiMgr.ApiCallStats.NumGetCallsSuccess++
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
	return
}

func GetOneStateObjectForId(w http.ResponseWriter, r *http.Request) {
	var obj, configObj, dbObj modelObjs.ConfigObj
	var objKey string
	var retObj ReturnObject
	var err error

	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseState), "/")[0]
	resource = strings.Split(resource, "?")[0]
	resource = strings.ToLower(resource)
        mylog("YORK, GetOneStateObjectForId, resource=" + resource+ ";urlStr=" + urlStr)

        if resource == "dpirules" {
            vars := mux.Vars(r)
            objId := vars["objId"]
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(objId)
            w.Write([]byte(js))
            mylog("YORK, GetOneStateObjectForId objId=" + objId)
            mylog("YORK, GetOneStateObjectForId js=" + js)
   
          return

        }

	configObjHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
		return
	}
	_, configObj, err = objects.GetConfigObjFromJsonData(r, configObjHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	resource = resource + "state"
	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
		return
	}
	_, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	vars := mux.Vars(r)
	uuid := vars["objId"]
	//if objId is provided then read objkey from DB
	objKey, err = gApiMgr.dbHdl.GetObjKeyFromUUID(uuid)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
	if resourceOwner.IsConnectedToServer() == false {
		errString := "Confd not connected to " + resourceOwner.GetServerName()
		RespondErrorForApiCall(w, SRSystemNotReady, errString)
		return
	}
	dbObj, err = gApiMgr.dbHdl.GetObjectFromDb(configObj, objKey)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	obj, _ = gApiMgr.dbHdl.MergeDbObjKeys(obj, dbObj)
	err, retObj.ConfigObj = resourceOwner.GetObject(obj, gApiMgr.dbHdl.DBUtil)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	retObj.ObjectId = uuid
	js, err := json.Marshal(retObj)
	if err == nil {
		gApiMgr.ApiCallStats.NumGetCallsSuccess++
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
	return
}

func GetOneStateObject(w http.ResponseWriter, r *http.Request) {
	var obj modelObjs.ConfigObj
	var objKey string
	var retObj ReturnObject
	var err error
	var uuid string

	gApiMgr.ApiCallStats.NumGetCalls++
	resource := ""
	queryData := ""
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource = strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseState), "/")[0]
	resource = strings.Split(resource, "?")[0]
	resource = strings.ToLower(resource) + "state"
        
        mylog("YORK, GetOneStateObject, resource=" + resource+ ";urlStr=" + urlStr)


        if resource == "dpirules" || resource == "dpirulesstate" || resource == "dpirulestate" {
            vars := mux.Vars(r)
            objId := vars["objId"]
            key := vars["key"]
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(objId)
            w.Write([]byte(js))
            mylog("YORK,BulkGetConfigObjects objId=" + objId)
            mylog("YORK,BulkGetConfigObjects key=" + key)
            mylog("YORK,BulkGetConfigObjects js=" + js)

         return

        }

	queryDataList := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseState), "?")
	if len(queryDataList) > 1 {
		queryData = queryDataList[1]
	}
	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	if queryData == "" {
		_, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
	} else {
		_, obj, err = objects.GetConfigObjFromQueryData(r, objHdl)
	}
	if err != nil || obj == nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	//Get key fields provided in the request.
	objKey = gApiMgr.dbHdl.GetKey(obj)
	resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
	if resourceOwner.IsConnectedToServer() == false {
		errString := "Confd not connected to " + resourceOwner.GetServerName()
		RespondErrorForApiCall(w, SRSystemNotReady, errString)
		return
	}
	err, retObj.ConfigObj = resourceOwner.GetObject(obj, gApiMgr.dbHdl.DBUtil)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	cfgObjKey := strings.Replace(objKey, "State", "", 1)
	uuid, err = gApiMgr.dbHdl.GetUUIDFromObjKey(cfgObjKey)
	retObj.ObjectId = uuid
	js, err := json.Marshal(retObj)
	if err == nil {
		gApiMgr.ApiCallStats.NumGetCallsSuccess++
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
	return
}

func BulkGetConfigObjects(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var configObjects []modelObjs.ConfigObj
	var resp GetBulkResponse
	var err error
	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig)
	resource = strings.ToLower(resource)
	resource = strings.Split(resource, "?")[0]
	resource = resource[:len(resource)-1]
	resource = strings.ToLower(resource)
        mylog("YORK, BulkGetConfigObjects, resource=" + resource+ ";urlStr=" + urlStr)


        if resource == "dpirules" {
            vars := mux.Vars(r)
            objId := vars["objId"]
            key := vars["key"]
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(objId)
            w.Write([]byte(js))
            mylog("YORK,BulkGetConfigObjects key=" + key)
            mylog("YORK,BulkGetConfigObjects objId=" + objId)
            mylog("YORK,BulkGetConfigObjects js=" + js)

         return

        }


	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	_, obj, err := objects.GetConfigObjFromJsonData(nil, objHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	currentIndex, objCount := ExtractGetBulkParams(r)
	if objCount > MAX_OBJECTS_IN_GETBULK {
		RespondErrorForApiCall(w, SRBulkGetTooLarge, err.Error())
		gApiMgr.logger.Err(fmt.Sprintln("Too many objects requested in bulkget ", objCount))
		return
	}
	resp.CurrentMarker = currentIndex
	err, resp.ObjCount, resp.NextMarker, resp.MoreExist,
		configObjects = gApiMgr.dbHdl.GetBulkObjFromDb(obj, currentIndex, objCount)
	if err == nil {
		sortedObjects := obj.SortObjList(configObjects)
		resp.Objects = make([]ReturnObject, resp.ObjCount)
		for idx, configObject := range sortedObjects {
			resp.Objects[idx].ConfigObj = configObject
			objKey = configObject.GetKey()
			resp.Objects[idx].ObjectId, err = gApiMgr.dbHdl.GetUUIDFromObjKey(objKey)
		}
		js, err := json.Marshal(resp)
		if err != nil {
			errCode = SRRespMarshalErr
			gApiMgr.logger.Err(fmt.Sprintln("### Error in marshalling JSON in getBulk for object ", resource, err))
		} else {
			gApiMgr.ApiCallStats.NumGetCallsSuccess++
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			w.Write(js)
			errCode = SRSuccess
		}
	}
	if errCode != SRSuccess {
		RespondErrorForApiCall(w, errCode, err.Error())
	}
	return
}

func BulkGetStateObjects(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var stateObjects []modelObjs.ConfigObj
	var resp GetBulkResponse
	var err error
	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.TrimPrefix(urlStr, gApiMgr.apiBaseState)
	resource = strings.Split(resource, "?")[0]
	resource = resource[:len(resource)-1]
	resource = strings.ToLower(resource) + "state"


        mylog("YORK, BulkGetStateObjects, resource=" + resource+ ";urlStr=" + urlStr)

       if resource == "dpirulestate" {
            vars := mux.Vars(r)
            objId := vars["objId"]
            key := vars["key"]
            mylog("YORK, BulkGetStateObjects key=" + key)
            mylog("YORK, BulkGetStateObjects objId=" + objId)
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(objId)
            w.Write([]byte(js))
            
            mylog("YORK, BulkGetStateObjects js=" + js)

         return

        }

	objHdl, ok := modelObjs.ConfigObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	_, obj, err := objects.GetConfigObjFromJsonData(nil, objHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	currentIndex, objCount := ExtractGetBulkParams(r)
	if objCount > MAX_OBJECTS_IN_GETBULK {
		RespondErrorForApiCall(w, SRBulkGetTooLarge, err.Error())
		gApiMgr.logger.Err(fmt.Sprintln("Too many objects requested in bulkget ", objCount))
		return
	}
	resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
	if resourceOwner.IsConnectedToServer() == false {
		errString := "Confd not connected to " + resourceOwner.GetServerName()
		RespondErrorForApiCall(w, SRSystemNotReady, errString)
		return
	}
	resp.CurrentMarker = currentIndex
	err, resp.ObjCount, resp.NextMarker, resp.MoreExist,
		stateObjects = resourceOwner.GetBulkObject(obj, gApiMgr.dbHdl.DBUtil, currentIndex, objCount)
	if err == nil {
		resp.Objects = make([]ReturnObject, resp.ObjCount)
		for idx, stateObject := range stateObjects {
			resp.Objects[idx].ConfigObj = stateObject
			objKey = stateObject.GetKey()
			cfgObjKey := strings.Replace(objKey, "State", "", 1)
			resp.Objects[idx].ObjectId, err = gApiMgr.dbHdl.GetUUIDFromObjKey(cfgObjKey)
		}
		js, err := json.Marshal(resp)
		if err != nil {
			errCode = SRRespMarshalErr
			gApiMgr.logger.Err(fmt.Sprintln("### Error in marshalling JSON in getBulk for object ", resource, err))
		} else {
			gApiMgr.ApiCallStats.NumGetCallsSuccess++
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			w.Write(js)
			errCode = SRSuccess
		}
	}
	if errCode != SRSuccess {
		RespondErrorForApiCall(w, errCode, err.Error())
	}
	return
}

func ExtractGetBulkParams(r *http.Request) (currentIndex int64, objectCount int64) {
	valueMap := r.URL.Query()
	if currentIndexStr, ok := valueMap["CurrentMarker"]; ok {
		currentIndex, _ = strconv.ParseInt(currentIndexStr[0], 10, 64)
	} else {
		currentIndex = 0
	}
	if objectCountStr, ok := valueMap["Count"]; ok {
		objectCount, _ = strconv.ParseInt(objectCountStr[0], 10, 64)
	} else {
		objectCount = MAX_OBJECTS_IN_GETBULK
	}
	return currentIndex, objectCount
}

func ExecuteActionObject(w http.ResponseWriter, r *http.Request) {
	var resp ActionResponse
	var errCode int
	var err error
	var actionobj modelActions.ActionObj
	var body []byte

	gApiMgr.ApiCallStats.NumActionCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	errCode = SRSuccess
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.TrimPrefix(urlStr, gApiMgr.apiBaseAction)
	resource = strings.ToLower(resource)
        mylog("YORK, ExecuteActionObject, resource=" + resource+ ";urlStr=" + urlStr)

	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, SRErrString(errCode))
		return
	}
	if actionobjHdl, ok := modelActions.ActionObjectMap[resource]; ok {
		fmt.Println("actionObjhdl:", actionobjHdl)
		if body, actionobj, err = actions.GetActionObj(r, actionobjHdl); err == nil {
			resourceOwner := gApiMgr.actionMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				errCode = SRSystemNotReady
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, errString)
				return
			}
			err = resourceOwner.ExecuteAction(actionobj)
			if err == nil {
				gApiMgr.ApiCallStats.NumActionCallsSuccess++
				w.WriteHeader(http.StatusOK)
				errCode = SRSuccess
				resp.Result = "Success"
			} else {
				resp.Result = err.Error()
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("Failed to execute action: ", actionobj, " due to error: ", err))
			}
		} else {
			errCode = SRObjHdlError
			gApiMgr.logger.Debug(fmt.Sprintln("Failed to get object handle from http request ", actionobjHdl, resource, err))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Failed to get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("ExecuteAction failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, "None")
	return
}

func ConfigObjectCreate(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var success bool
	var uuid string
	var objKey string
	var err error
	var obj modelObjs.ConfigObj
	var body []byte

	gApiMgr.ApiCallStats.NumCreateCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	errCode = SRSuccess
	resp := &ConfigResponse{}
	resp.FillBaseConfigResponse()
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig)
	resource = strings.ToLower(resource)
        mylog("YORK, ConfigObjectCreate, resource=" + resource+ ";urlStr=" + urlStr)

       if resource == "dpirules" {
            name := "" 
            body, err := ioutil.ReadAll(io.LimitReader(r.Body, 8096))
            if err != nil {
               mylog("YORK, ConfigObjectCreate ,err TRUE")
            }
            bodys := bytes.NewBuffer(body).String()
            if bodys != "" {
               var file RuleFile
               err := json.Unmarshal(body, &file)
               if err != nil {
                   mylog("YORK, ConfigObjectCreate json.Unmarshal error" )
                }else{
                   name = file.Name
                   mylog("YORK, ConfigObjectCreate, name=" + name)
                   updateRules(file)
                }
            }
            
            mylog("YORK, ConfigObjectCreate name=" + name)
            gApiMgr.ApiCallStats.NumGetCallsSuccess++
            w.Header().Set("Content-Type", "application/json; charset=UTF-8")
            w.WriteHeader(http.StatusOK)
            js := dpiMarshal(name)
            w.Write([]byte(js))
            mylog("YORK,ConfigObjectCreate js=" + js) 
            return 
      } 


	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, SRErrString(errCode))
		return
	}
	if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
		if body, obj, err = objects.GetConfigObjFromJsonData(r, objHdl); err == nil {
			updateKeys, _ := objects.GetUpdateKeys(body)
			if len(updateKeys) == 0 {
				errCode = SRNoContent
				gApiMgr.logger.Debug("Nothing to configure")
			} else {
				objKey = gApiMgr.dbHdl.GetKey(obj)
				uuid, err = gApiMgr.dbHdl.GetUUIDFromObjKey(objKey)
				if err == nil {
					errCode = SRAlreadyConfigured
					gApiMgr.logger.Debug("Config object is present")
				}
			}
			if errCode != SRSuccess {
				w.WriteHeader(http.StatusInternalServerError)
				resp.UUId = uuid
				resp.Result = SRErrString(errCode)
				js, _ := json.Marshal(resp)
				w.Write(js)
				gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, SRErrString(errCode))
				return
			}
			resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errCode = SRSystemNotReady
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, errString)
				return
			}
			err, success = resourceOwner.CreateObject(obj, gApiMgr.dbHdl.DBUtil)
			if success == true {
				uuid, dbErr := gApiMgr.dbHdl.StoreUUIDToObjKeyMap(objKey)
				if dbErr == nil {
					gApiMgr.ApiCallStats.NumCreateCallsSuccess++
					w.WriteHeader(http.StatusCreated)
					resp.UUId = uuid
					errCode = SRSuccess
					resp.Result = "Success"
				} else {
					errCode = SRIdStoreFail
					gApiMgr.logger.Debug(fmt.Sprintln("Failed to store UuidToKey map ", obj, dbErr))
				}
			} else {
				if err != nil {
					resp.Result = err.Error()
				}
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("Failed to create object: ", obj, " due to error: ", err))
			}
		} else {
			errCode = SRObjHdlError
			gApiMgr.logger.Debug(fmt.Sprintln("Failed to get object handle from http request ", objHdl, resource, err))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Failed to get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if err != nil && errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode) + " " + err.Error()
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("CreateObject failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "POST", body, errCode, "None")
	return
}

func ConfigObjectUpdateDeleteDpi(deleteUpdate string, r *http.Request) string {
      urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
      queryDataList := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "?")
      queryData :=""
      if len(queryDataList) > 1 {
         queryData = queryDataList[1]
      }
      name :=""
      mylog("YORK, ConfigObjectUpdateDeleteDpi,queryData=" + queryData) 
      if queryData == "" {
         body, err := ioutil.ReadAll(io.LimitReader(r.Body, 4096))
         if err != nil {
            mylog("YORK, ConfigObjectUpdateDeleteDpi,err TRUE")
         }
         bodys := bytes.NewBuffer(body).String()
         if bodys != "" { 
            var file RuleFile
            err := json.Unmarshal(body, &file)
            if err != nil {
                mylog("YORK, onfigObjectUpdateDeleteDpi json.Unmarshal error" )
            }else{
                name = file.Name 
                if strings.ToLower(deleteUpdate) == "delete" || strings.ToLower(deleteUpdate) == "del" {
                    delRules(file)
                     mylog("YORK, ConfigObjectUpdateDeleteDpi, delRules ")
                }else {
                    mylog("YORK, ConfigObjectUpdateDeleteDpi,  updateRules")
                    updateRules(file)
                }
            }
        }
     } 
     return name

}

func ConfigObjectDeleteForId(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var success bool
	var err error
	var obj modelObjs.ConfigObj
	var body []byte

	gApiMgr.ApiCallStats.NumDeleteCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resp := &ConfigResponse{}
	resp.FillBaseConfigResponse()
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.ToLower(resource)
        
        mylog("YORK, ConfigObjectDeleteForId, resource=" + resource+ ";urlStr=" + urlStr)
        if resource == "dpirules" {
           //DPI delete fhere 
            name :=ConfigObjectUpdateDeleteDpi("delete",r)       

           gApiMgr.ApiCallStats.NumGetCallsSuccess++
           w.Header().Set("Content-Type", "application/json; charset=UTF-8")
           w.WriteHeader(http.StatusOK)
           js := dpiMarshal(name)
           w.Write([]byte(js))
           mylog("YORK, GetOneConfigObject js=" + js)
           return

        }
 
	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, SRErrString(errCode))
		return
	}
	vars := mux.Vars(r)
	resp.UUId = vars["objId"]
	objKey, err = gApiMgr.dbHdl.GetObjKeyFromUUID(vars["objId"])
	if err != nil {
		errCode = SRNotFound
		w.WriteHeader(http.StatusNotFound)
		resp.Result = SRErrString(errCode)
		js, _ := json.Marshal(resp)
		w.Write(js)
		gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, SRErrString(errCode))
		return
	}
	if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
		if body, obj, err = objects.GetConfigObjFromJsonData(nil, objHdl); err == nil {
			dbObj, _ := gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
			resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				errCode = SRSystemNotReady
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, errString)
				return
			}
			err, success = resourceOwner.DeleteObject(dbObj, objKey, gApiMgr.dbHdl.DBUtil)
			if success == true {
				err = gApiMgr.dbHdl.DeleteUUIDToObjKeyMap(vars["objId"], objKey)
				if err != nil {
					errCode = SRIdDeleteFail
					gApiMgr.logger.Debug(fmt.Sprintln("Failure in deleting Uuid map entry for ", vars["objId"], err))
				} else {
					gApiMgr.ApiCallStats.NumDeleteCallsSuccess++
					w.WriteHeader(http.StatusGone)
					errCode = SRSuccess
					resp.Result = "Success"
				}
			} else {
				if err != nil {
					resp.Result = err.Error()
				}
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("DeleteObject returned failure ", obj, err))
			}
		} else {
			errCode = SRObjHdlError
			gApiMgr.logger.Debug(fmt.Sprintln("Failed to get object handle from http request ", objHdl, err))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Failed to get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("DeleteObject failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, "None")
	return
}

func ConfigObjectDelete(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var success bool
	var uuid string
	var err error
	var obj modelObjs.ConfigObj
	var body []byte

	gApiMgr.ApiCallStats.NumDeleteCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resp := &ConfigResponse{}
	resp.FillBaseConfigResponse()
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.ToLower(resource)
        mylog("YORK, ConfigObjectDelete, resource=" + resource+ ";urlStr=" + urlStr)


        if resource == "dpirules" {
           //DPI delete fhere
            name :=ConfigObjectUpdateDeleteDpi("delete",r)

           gApiMgr.ApiCallStats.NumGetCallsSuccess++
           w.Header().Set("Content-Type", "application/json; charset=UTF-8")
           w.WriteHeader(http.StatusOK)
           js := dpiMarshal(name)
           w.Write([]byte(js))
           mylog("YORK, GetOneConfigObject js=" + js)
           return

        }

	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, SRErrString(errCode))
		return
	}
	if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
		if body, obj, err = objects.GetConfigObjFromJsonData(r, objHdl); err == nil {
			objKey = gApiMgr.dbHdl.GetKey(obj)
			dbObj, err := gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
			if err != nil {
				errCode = SRNotFound
				w.WriteHeader(http.StatusNotFound)
				resp.Result = SRErrString(errCode)
				js, _ := json.Marshal(resp)
				w.Write(js)
				gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, SRErrString(errCode))
				return
			}
			uuid, err = gApiMgr.dbHdl.GetUUIDFromObjKey(objKey)
			resp.UUId = uuid
			resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				errCode = SRSystemNotReady
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, errString)
				return
			}
			err, success = resourceOwner.DeleteObject(dbObj, objKey, gApiMgr.dbHdl.DBUtil)
			if success == true {
				err = gApiMgr.dbHdl.DeleteUUIDToObjKeyMap(uuid, objKey)
				if err != nil {
					errCode = SRIdDeleteFail
					gApiMgr.logger.Debug(fmt.Sprintln("Failure in deleting Uuid map entry for ", uuid, err))
				} else {
					gApiMgr.ApiCallStats.NumDeleteCallsSuccess++
					w.WriteHeader(http.StatusGone)
					errCode = SRSuccess
					resp.Result = "Success"
				}
			} else {
				if err != nil {
					resp.Result = err.Error()
				}
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("DeleteObject returned failure ", obj))
			}
		} else {
			errCode = SRObjHdlError
			gApiMgr.logger.Debug(fmt.Sprintln("Failed to get object handle from http request ", objHdl, err))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Failed to get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("DeleteObject failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "DELETE", body, errCode, "None")
	return
}

func ConfigObjectUpdateForId(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var success bool
	var err error
	var obj modelObjs.ConfigObj
	var body []byte

	gApiMgr.ApiCallStats.NumUpdateCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resp := &ConfigResponse{}
	resp.FillBaseConfigResponse()
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.ToLower(resource)
        mylog("YORK, ConfigObjectUpdateForId, resource=" + resource+ ";urlStr=" + urlStr)

        if resource == "dpirules" {
           //DPI delete fhere
            name :=ConfigObjectUpdateDeleteDpi("update",r)

           gApiMgr.ApiCallStats.NumGetCallsSuccess++
           w.Header().Set("Content-Type", "application/json; charset=UTF-8")
           w.WriteHeader(http.StatusOK)
           js := dpiMarshal(name)
           w.Write([]byte(js))
           mylog("YORK, GetOneConfigObject js=" + js)
           return

        }

	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
		return
	}
	vars := mux.Vars(r)
	resp.UUId = vars["objId"]
	objKey, err = gApiMgr.dbHdl.GetObjKeyFromUUID(vars["objId"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		errCode = SRNotFound
		resp.Result = SRErrString(errCode)
		js, _ := json.Marshal(resp)
		w.Write(js)
		gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
		return
	}
	if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
		body, obj, _ = objects.GetConfigObjFromJsonData(r, objHdl)
		updateKeys, _ := objects.GetUpdateKeys(body)
		dbObj, gerr := gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
		if gerr == nil {
			patchOpInfoSlice := make([]modelObjs.PatchOpInfo, 0)
			if strings.Contains(string(body), "\"patch\":") {
				patches := strings.SplitAfter(string(body), "\"patch\":")[1]
				patches = strings.TrimSuffix(patches, "}")
				patchStr, err := objects.GetPatch([]byte(patches))
				if err != nil {
					errCode = SRPatchDecodeError
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
					RespondErrorForApiCall(w, errCode, SRErrString(errCode))
					return
				}
				for _, ops := range patchStr {
					opStr, err := objects.GetOp(ops)
					if err != nil {
						errCode = SRPatchDecodeError
						gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
						RespondErrorForApiCall(w, errCode, SRErrString(errCode))
						return
					}
					pathStr, err := objects.GetPath(ops)
					if err != nil {
						errCode = SRPatchDecodeError
						gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
						RespondErrorForApiCall(w, errCode, SRErrString(errCode))
						return
					}
					value, ok := ops["value"]
					if !ok {
						errCode = SRPatchDecodeError
						gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
						RespondErrorForApiCall(w, errCode, SRErrString(errCode))
						return
					}
					patchOpInfo := modelObjs.PatchOpInfo{opStr, pathStr, string(*value)}
					patchOpInfoSlice = append(patchOpInfoSlice, patchOpInfo)
				}
				resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
				if resourceOwner.IsConnectedToServer() == false {
					errString := "Confd not connected to " + resourceOwner.GetServerName()
					errCode = SRSystemNotReady
					RespondErrorForApiCall(w, errCode, errString)
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, errString)
					return
				}
				mergedObj, diff, err := gApiMgr.dbHdl.MergeDbAndConfigObjForPatchUpdate(obj, dbObj, patchOpInfoSlice)
				if err != nil {
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode)+err.Error())
					RespondErrorForApiCall(w, errCode, err.Error())
					return
				}
				err, success = resourceOwner.UpdateObject(dbObj, mergedObj, diff, patchOpInfoSlice, objKey, gApiMgr.dbHdl.DBUtil)
				if success == true {
					gApiMgr.ApiCallStats.NumUpdateCallsSuccess++
					w.WriteHeader(http.StatusOK)
					errCode = SRSuccess
					resp.Result = "Success"
				} else {
					if err != nil {
						resp.Result = err.Error()
					}
					gApiMgr.logger.Debug(fmt.Sprintln("UpdateObject failed for resource ", updateKeys, resource))
					errCode = SRServerError
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
					RespondErrorForApiCall(w, errCode, SRErrString(errCode))
					return
				}
				js, err := json.Marshal(resp)
				if err != nil {
					gApiMgr.logger.Debug("UpdateObject failed to Marshal config response")
				}
				w.Write(js)
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, "None")
				return
			}
			diff, _ := gApiMgr.dbHdl.CompareObjectsAndDiff(obj, updateKeys, dbObj)
			anyUpdated := false
			for _, updated := range diff {
				if updated == true {
					anyUpdated = true
					break
				}
			}
			if anyUpdated == false {
				w.WriteHeader(http.StatusInternalServerError)
				errCode = SRUpdateNoChange
				resp.Result = SRErrString(errCode)
				js, _ := json.Marshal(resp)
				w.Write(js)
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
				return
			}
			mergedObj, _ := gApiMgr.dbHdl.MergeDbAndConfigObj(obj, dbObj, diff)
			mergedObjKey := gApiMgr.dbHdl.GetKey(mergedObj)
			if objKey == mergedObjKey {
				resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
				if resourceOwner.IsConnectedToServer() == false {
					errString := "Confd not connected to " + resourceOwner.GetServerName()
					errCode = SRSystemNotReady
					RespondErrorForApiCall(w, errCode, errString)
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, errString)
					return
				}
				//Perform pre update validation
				err = resourceOwner.PreUpdateValidation(dbObj, mergedObj, diff, gApiMgr.dbHdl.DBUtil)
				if err != nil {
					errCode = SRValidationFailed
					RespondErrorForApiCall(w, errCode, err.Error())
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode)+err.Error())
					return
				}
				err, success = resourceOwner.UpdateObject(dbObj, mergedObj, diff, patchOpInfoSlice, objKey, gApiMgr.dbHdl.DBUtil)
				if success == true {
					//Perform post update processing
					_ = resourceOwner.PostUpdateProcessing(dbObj, mergedObj, diff, gApiMgr.dbHdl.DBUtil)
					gApiMgr.ApiCallStats.NumUpdateCallsSuccess++
					w.WriteHeader(http.StatusOK)
					errCode = SRSuccess
					resp.Result = "Success"
				} else {
					if err != nil {
						resp.Result = err.Error()
					}
					errCode = SRServerError
					gApiMgr.logger.Debug(fmt.Sprintln("UpdateObject failed for resource ", updateKeys, resource))
				}
			} else {
				errCode = SRUpdateKeyError
				gApiMgr.logger.Debug(fmt.Sprintln("Cannot update key ", updateKeys, resource))
			}
		} else {
			errCode = SRObjHdlError
			gApiMgr.logger.Debug(fmt.Sprintln("Config update failed in getting obj via objKey ", objKey, gerr))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Config update failed t get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("UpdateObject failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, "None")
	return
}

func ConfigObjectUpdate(w http.ResponseWriter, r *http.Request) {
	var errCode int
	var objKey string
	var success bool
	var uuid string
	var err error
	var obj modelObjs.ConfigObj
	var body []byte

	gApiMgr.ApiCallStats.NumUpdateCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resp := &ConfigResponse{}
	resp.FillBaseConfigResponse()
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseConfig), "/")[0]
	resource = strings.ToLower(resource)
        mylog("YORK, ConfigObjectUpdate, resource=" + resource+ ";urlStr=" + urlStr)
        
        if resource == "dpirules" {
           //DPI delete fhere
           name :=ConfigObjectUpdateDeleteDpi("update",r)

           gApiMgr.ApiCallStats.NumGetCallsSuccess++
           w.Header().Set("Content-Type", "application/json; charset=UTF-8")
           w.WriteHeader(http.StatusOK)
           js := dpiMarshal(name)
           w.Write([]byte(js))
           mylog("YORK, GetOneConfigObject js=" + js)
           return

        }
	if gApiMgr.clientMgr.IsReady() == false {
		errCode = SRSystemNotReady
		RespondErrorForApiCall(w, errCode, "")
		gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
		return
	}
	if objHdl, ok := modelObjs.ConfigObjectMap[resource]; ok {
		body, obj, err = objects.GetConfigObjFromJsonData(r, objHdl)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			errCode = SRUnmarshalError
			resp.Result = err.Error()
			js, _ := json.Marshal(resp)
			w.Write(js)
			gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode)+err.Error())
			return
		}
		objKey = gApiMgr.dbHdl.GetKey(obj)
		updateKeys, _ := objects.GetUpdateKeys(body)
		dbObj, gerr := gApiMgr.dbHdl.GetObjectFromDb(obj, objKey)
		if gerr != nil {
			w.WriteHeader(http.StatusNotFound)
			errCode = SRNotFound
			resp.Result = SRErrString(errCode)
			js, _ := json.Marshal(resp)
			w.Write(js)
			gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
			return
		}
		uuid, err = gApiMgr.dbHdl.GetUUIDFromObjKey(objKey)
		resp.UUId = uuid
		patchOpInfoSlice := make([]modelObjs.PatchOpInfo, 0)
		if strings.Contains(string(body), "\"patch\":") {
			diff := make([]bool, ((reflect.TypeOf(obj)).NumField()))
			patches := strings.SplitAfter(string(body), "\"patch\":")[1]
			patches = strings.TrimSuffix(patches, "}")
			patchStr, err := objects.GetPatch([]byte(patches))
			if err != nil {
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
				return
			}
			for _, ops := range patchStr {
				opStr, err := objects.GetOp(ops)
				if err != nil {
					errCode = SRPatchDecodeError
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
					RespondErrorForApiCall(w, errCode, SRErrString(errCode))
					return
				}
				pathStr, err := objects.GetPath(ops)
				if err != nil {
					errCode = SRPatchDecodeError
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
					RespondErrorForApiCall(w, errCode, SRErrString(errCode))
					return
				}
				value, ok := ops["value"]
				if !ok {
					errCode = SRPatchDecodeError
					gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
					RespondErrorForApiCall(w, errCode, SRErrString(errCode))
					return
				}
				patchOpInfo := modelObjs.PatchOpInfo{opStr, pathStr, string(*value)}
				patchOpInfoSlice = append(patchOpInfoSlice, patchOpInfo)
			}
			resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				errCode = SRSystemNotReady
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, errString)
				return
			}
			mergedObj, diff, err := gApiMgr.dbHdl.MergeDbAndConfigObjForPatchUpdate(obj, dbObj, patchOpInfoSlice)
			if err != nil {
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
				RespondErrorForApiCall(w, errCode, SRErrString(errCode))
				return
			}
			err, success = resourceOwner.UpdateObject(dbObj, mergedObj, diff, patchOpInfoSlice, objKey, gApiMgr.dbHdl.DBUtil)
			if success == true {
				gApiMgr.ApiCallStats.NumUpdateCallsSuccess++
				w.WriteHeader(http.StatusOK)
				errCode = SRSuccess
				resp.Result = "Success"
			} else {
				if err != nil {
					resp.Result = err.Error()
				}
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("UpdateObject failed for resource ", updateKeys, resource))
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
				RespondErrorForApiCall(w, errCode, SRErrString(errCode))
				return
			}
			js, err := json.Marshal(resp)
			if err != nil {
				gApiMgr.logger.Debug("UpdateObject failed to Marshal config response")
			}
			w.Write(js)
			gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, "None")
			return
		}
		diff, _ := gApiMgr.dbHdl.CompareObjectsAndDiff(obj, updateKeys, dbObj)
		anyUpdated := false
		for _, updated := range diff {
			if updated == true {
				anyUpdated = true
				break
			}
		}
		if anyUpdated == false {
			w.WriteHeader(http.StatusInternalServerError)
			errCode = SRUpdateNoChange
			resp.Result = SRErrString(errCode)
			js, _ := json.Marshal(resp)
			w.Write(js)
			gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode))
			return
		}

		mergedObj, _ := gApiMgr.dbHdl.MergeDbAndConfigObj(obj, dbObj, diff)
		mergedObjKey := mergedObj.GetKey()
		if objKey == mergedObjKey {
			resourceOwner := gApiMgr.objectMgr.ObjHdlMap[resource].Owner
			if resourceOwner.IsConnectedToServer() == false {
				errString := "Confd not connected to " + resourceOwner.GetServerName()
				errCode = SRSystemNotReady
				RespondErrorForApiCall(w, errCode, errString)
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, errString)
				return
			}
			//Perform pre update validation
			err = resourceOwner.PreUpdateValidation(dbObj, mergedObj, diff, gApiMgr.dbHdl.DBUtil)
			if err != nil {
				errCode = SRValidationFailed
				RespondErrorForApiCall(w, errCode, err.Error())
				gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, SRErrString(errCode)+err.Error())
				return
			}
			err, success = resourceOwner.UpdateObject(dbObj, mergedObj, diff, patchOpInfoSlice, objKey, gApiMgr.dbHdl.DBUtil)
			if success == true {
				//Perform post update processing
				_ = resourceOwner.PostUpdateProcessing(dbObj, mergedObj, diff, gApiMgr.dbHdl.DBUtil)
				gApiMgr.ApiCallStats.NumUpdateCallsSuccess++
				w.WriteHeader(http.StatusOK)
				errCode = SRSuccess
				resp.Result = "Success"
			} else {
				if err != nil {
					resp.Result = err.Error()
				}
				errCode = SRServerError
				gApiMgr.logger.Debug(fmt.Sprintln("UpdateObject failed for resource ", updateKeys, resource))
			}
		} else {
			errCode = SRUpdateKeyError
			gApiMgr.logger.Debug(fmt.Sprintln("Cannot update key ", updateKeys, resource))
		}
	} else {
		errCode = SRObjMapError
		gApiMgr.logger.Debug(fmt.Sprintln("Config update failed cannot get ObjectMap ", resource))
	}

	if errCode != SRSuccess {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errCode != SRServerError && errCode != SRSuccess {
		resp.Result = SRErrString(errCode)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		gApiMgr.logger.Debug("UpdateObject failed to Marshal config response")
	}
	w.Write(js)
	gApiMgr.StoreApiCallInfo(r, resource, "UPDATE", body, errCode, "None")
	return
}

//func GetAPIDocs(w http.ResponseWriter, r *http.Request) {
//	logger.Println("### GetAPIDocs is called")
//	//fp := path.Join("./", "api-docs.json")

//	w.Header().Set("Access-Control-Allow-Origin", "*")
//	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT")
//	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, api_key, Authorization")
//	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
//	w.WriteHeader(http.StatusOK)

//	//http.ServeFile(w, r, fp)
//	return
//}

//func GetObjectAPIDocs(w http.ResponseWriter, r *http.Request) {
//	logger.Println("### GetObjectAPIDocs is called")
//	//fp := path.Join("./", "greetings.json")
//	//http.ServeFile(w, r, fp)
//	return
//}

func EventObjectGet(w http.ResponseWriter, r *http.Request) {
	var obj modelEvents.EventObj
	var retObj GetEventResponse
	var err error

	gApiMgr.ApiCallStats.NumGetCalls++
	urlStr := ReplaceMultipleSeperatorInUrl(r.URL.String())
	resource := strings.Split(strings.TrimPrefix(urlStr, gApiMgr.apiBaseEvent), "/")[0]
	resource = strings.ToLower(resource)
        mylog("YORK, EventObjectGet, resource=" + resource+ ";urlStr=" + urlStr)

	objHdl, ok := modelEvents.EventObjectMap[resource]
	if !ok {
		RespondErrorForApiCall(w, SRNotFound, "")
	}
	_, obj, err = objects.GetEventObj(r, objHdl)
	if err != nil {
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	evtObjList, err := eventUtils.GetEvents(obj, gApiMgr.dbHdl.DBUtil, gApiMgr.logger)
	if err != nil {
		gApiMgr.logger.Err(fmt.Sprintln("Error extracting events", err))
		RespondErrorForApiCall(w, SRNotFound, err.Error())
		return
	}
	retObj.Objects = evtObjList
	w.WriteHeader(http.StatusOK)
	js, err := json.Marshal(retObj)
	if err != nil {
		gApiMgr.logger.Err("Error marshalling the object")
	}
	w.Write(js)
	return
}
