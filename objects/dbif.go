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
	"github.com/garyburd/redigo/redis"
	"github.com/nu7hatch/gouuid"
	"strings"
	"utils/dbutils"
	"utils/logging"
)

type DbHandler struct {
	*dbutils.DBUtil
	logger *logging.Writer
}

//  This method initializes the db handler
func InstantiateDbIf(logger *logging.Writer) *DbHandler {
	var err error

	dbHdl := new(DbHandler)
	dbHdl.DBUtil = dbutils.NewDBUtil(logger)
	err = dbHdl.DBUtil.Connect()
	if err != nil {
		logger.Err("Failed to dial out to Redis server")
		return nil
	}
	dbHdl.logger = logger
	return dbHdl
}

func (d *DbHandler) DisconnectDbIf() {
	d.Disconnect()
	return
}

func (d *DbHandler) StoreUUIDToObjKeyMap(objKey string) (string, error) {
	UUId, err := uuid.NewV4()
	if err != nil {
		d.logger.Err("Failed to get UUID " + err.Error())
		return "", err
	}
	defer d.DBUtil.DbLock.Unlock()
	d.DBUtil.DbLock.Lock()
	_, err = d.Do("SET", UUId.String(), objKey)
	if err != nil {
		d.logger.Err("Failed to insert uuid to objkey entry in db " + err.Error())
		return "", err
	}
	objKeyWithUUIDPrefix := "UUID" + objKey
	_, err = d.Do("SET", objKeyWithUUIDPrefix, UUId.String())
	if err != nil {
		d.logger.Err("Failed to insert objkey to uuid entry in db " + err.Error())
		return "", err
	}
	return UUId.String(), nil
}

func (d *DbHandler) DeleteUUIDToObjKeyMap(uuid, objKey string) error {
	defer d.DBUtil.DbLock.Unlock()
	d.DBUtil.DbLock.Lock()
	_, err := d.Do("DEL", uuid)
	if err != nil {
		d.logger.Err("Failed to delete uuid to objkey entry in db " + err.Error())
		return err
	}
	objKeyWithUUIDPrefix := "UUID" + objKey
	_, err = d.Do("DEL", objKeyWithUUIDPrefix)
	if err != nil {
		d.logger.Err("Failed to delete objkey to uuid entry in db " + err.Error())
		return err
	}
	return nil
}

func (d *DbHandler) GetUUIDFromObjKey(objKey string) (string, error) {
	defer d.DBUtil.DbLock.Unlock()
	d.DBUtil.DbLock.Lock()
	objKeyWithUUIDPrefix := "UUID" + objKey
	uuid, err := redis.String(d.Do("GET", objKeyWithUUIDPrefix))
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func (d *DbHandler) GetObjKeyFromUUID(uuid string) (string, error) {
	defer d.DBUtil.DbLock.Unlock()
	d.DBUtil.DbLock.Lock()
	objKey, err := redis.String(d.Do("GET", uuid))
	if err != nil {
		return "", err
	}
	objKey = strings.TrimRight(objKey, "UUID")
	return objKey, nil
}
