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

package main

import (
	"config/server"
	"flag"
	"fmt"
	"net/http"
	"utils/keepalive"
	"utils/logging"
)

func main() {
	fmt.Println("Starting ConfigMgr daemon")
	paramsDir := flag.String("params", "./params", "Directory Location for config files")
	flag.Parse()
	paramsDirName := *paramsDir
	if paramsDirName[len(paramsDirName)-1] != '/' {
		paramsDirName = paramsDirName + "/"
	}

	fmt.Println("ConfigMgr: Start logger")
	logger, err := logging.NewLogger("confd", "ConfigMgr", true)
	if err != nil {
		fmt.Println("Failed to start logger. Nothing will be logged ...")
	}

	configMgr := server.NewConfigMgr(paramsDirName, logger)
	if configMgr == nil {
		logger.Err("Failed to initialize CONF Mgr. Exiting!!!")
		return
	}
	restRtr := configMgr.ApiMgr.GetRestRtr()

	// Start keepalive routine
	go keepalive.InitKeepAlive("confd", paramsDirName)

	foundConfPort, confPort := server.GetConfigHandlerPort(paramsDirName)
	if foundConfPort {
		logger.Info("Starting config listener on port:", confPort)
		err = http.ListenAndServe(":"+confPort, restRtr)
	} else {
		logger.Info("Starting config listener on port: 8080")
		err = http.ListenAndServe(":8080", restRtr)
	}
	if err != nil {
		logger.Err("Failed to start config listener:", err)
	}
	panic("ConfigMgr Exiting!!!")
}
