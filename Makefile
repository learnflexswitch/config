RM=rm -f
DESTDIR=$(SR_CODE_BASE)/snaproute/src/out/bin
PARAMSDIR=$(DESTDIR)/params
SYSPROFILE=$(DESTDIR)/sysprofile
MKDIR=mkdir -p
RSYNC=rsync -rupE
GOLDFLAGS=-r /opt/flexswitch/sharedlib
SRCS=main.go
COMP_NAME=confd

all: gencode exe install 

exe: $(SRCS)
	go build -ldflags="$(GOLDFLAGS)" -o $(DESTDIR)/$(COMP_NAME) $(SRCS)
	$(SR_CODE_BASE)/snaproute/src/config/docgen/gendoc.sh

install:
	 @$(MKDIR) $(PARAMSDIR)
	 #@$(MKDIR) $(SYSPROFILE)
	 @$(RSYNC) docsui $(PARAMSDIR)
	 -@$(RSYNC) $(SR_CODE_BASE)/snaproute/src/flexui $(PARAMSDIR)
	 @echo $(DESTDIR)
	 install params/* $(PARAMSDIR)/
	 install $(SR_CODE_BASE)/snaproute/src/models/objects/systemProfile.json $(PARAMSDIR)
	 install $(SR_CODE_BASE)/snaproute/src/models/objects/genObjectConfig.json $(PARAMSDIR)
	 install $(SR_CODE_BASE)/snaproute/src/models/actions/genObjectAction.json $(PARAMSDIR)
	 install $(SR_CODE_BASE)/snaproute/src/config/actions/configOrder.json $(PARAMSDIR)


fmt: $(SRCS)
	 go fmt $(SRCS)

gencode:
	$(SR_CODE_BASE)/reltools/codegentools/gencode.sh

guard:
ifndef SR_CODE_BASE
	 $(error SR_CODE_BASE is not set)
endif

clean:guard
	 $(RM) $(DESTDIR)/$(COMP_NAME) 
