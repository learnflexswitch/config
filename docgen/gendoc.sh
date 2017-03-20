#!/bin/bash
cd $SR_CODE_BASE/snaproute/src/config/docgen/
go run *.go
mv $SR_CODE_BASE/snaproute/src/config/docgen/allObjs.json $SR_CODE_BASE/snaproute/src/config/docsui/index.html
mv $SR_CODE_BASE/snaproute/src/config/docgen/cfgObjs.json $SR_CODE_BASE/snaproute/src/config/docsui/config.html
mv $SR_CODE_BASE/snaproute/src/config/docgen/stateObjs.json $SR_CODE_BASE/snaproute/src/config/docsui/state.html
