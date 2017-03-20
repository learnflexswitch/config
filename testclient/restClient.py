
import wx
import os
import json
import requests
import wx.grid

HOME = os.getenv("HOME")
MODEL_NAME = 'models/objects'
JSON_MODEL_REGISTRAION_PATH = HOME + "/git/snaproute/src/models/objects/"
GO_MODEL_BASE_PATH_LIST = [
                           HOME + "/git/snaproute/src/models/objects/"]

LOCAL_HOST_URL = "http://localhost:8080/"

aboutText = """<p>Sorry, there is no information about this program. It is
  running on version %(wxpy)s of <b>wxPython</b> and %(python)s of <b>Python</b>.
  See <a href="http://wiki.wxpython.org">wxPython Wiki</a></p>"""

class_bool_map = {
  'false':  False,
  'False':  False,
  'true':    True,
  'True':    True,
}

class_map = {
  # this map is dynamically built upon but defines how we take
  # a YANG type  and translate it into a native Python class
  # along with other attributes that are required for this mapping.
  #
  # key:                the name of the YANG type
  # native_type:        the GO type that is used to support this
  #                     YANG type natively.
  # map (optional):     a map to take input values and translate them
  #                     into valid values of the type.
  # base_type:          whether the class can be used as class(*args, **kwargs)
  #                     in Python, or whether it is a derived class (such as is
  #                     created based on a typedef, or for types that cannot be
  #                     supported natively, such as enumeration, or a string
  #                     with a restriction placed on it)
  # quote_arg (opt):    whether the argument to this class' __init__ needs to be
  #                     quoted (e.g., str("hello")) in the code that is output.
  # pytype (opt):       A reference to the actual type that is used, this is
  #                     used where we infer types, such as for an input value to
  #                     a union since we need to actually compare the value
  #                     against the __init__ method and see whether it works.
  # parent_type (opt):  for "derived" types, then we store what the enclosed
  #                     type is such that we can create instances where required
  #                     e.g., a restricted string will have a parent_type of a
  #                     string. this can be a list if the type is a union.
  # restriction ...:    where the type is a restricted type, then the class_map
  # (optional)          dict entry can store more information about the type of
  #                     restriction. this is generally used when we need to
  #                     re-initialise an instance of the class, such as in the
  #                     setter methods of containers.
  # Other types may add their own types to this dictionary that have meaning
  # only for themselves. For example, a ReferenceType can add the path that it
  # references, and whether the require-instance keyword was set or not.
  'bool':          {"native_type": "bool", "map": class_bool_map,
                          "base_type": True, "quote_arg": True},
  'binary':           {"native_type": "bitarray", "base_type": True,
                          "quote_arg": True},
  'uint8':            {"native_type": "uint8", "base_type": True, "max": "^uint8(0)"},
  'uint16':           {"native_type": "uint16", "base_type": True, "max": "^uint16(0)"},
  'uint32':           {"native_type": "uint32", "base_type": True, "max": "^uint32(0)"},
  'uint64':           {"native_type": "uint64", "base_type": True, "max": "^uint64(0)"},
  'string':           {"native_type": "string", "base_type": True,
                          "quote_arg": True},
  'decimal64':        {"native_type": "float64", "base_type": True},
  'empty':            {"native_type": "bool", "map": class_bool_map,
                          "base_type": True, "quote_arg": True},
  'int8':             {"native_type": "int8", "base_type": True, "max": "^int8(0)"},
  'int16':            {"native_type": "int16", "base_type": True, "max": "^int16(0)"},
  'int32':            {"native_type": "int32", "base_type": True, "max": "^uint32(0)"},
  'int64':            {"native_type": "int64", "base_type": True, "max": "^uint64(0)"},
}


def scan_dir_for_json_files(dir):
    for name in os.listdir(dir):
        #print "x", dir, name
        path = os.path.join(dir, name)
        if name.endswith('.json'):
            if os.path.isfile(path):
                yield (dir, name)
        #elif not "." in name:
        #    for d, f  in scan_dir_for_go_files(path):
        #        yield (d, f)

def get_registered_structs_from_json(goStructsList):
    for dir, jsonfilename in scan_dir_for_json_files(JSON_MODEL_REGISTRAION_PATH):
        path = os.path.join(dir, jsonfilename)
        structList = []
        with open(path, 'r') as f:
            data = json.load(f)

            for k, v in data.iteritems():
                if v["Owner"] or v["Listeners"]:
                    structList.append(k)

            goStructsList.append((jsonfilename.split('.')[0], structList))

def scan_dir_for_go_files(dir):
    for name in os.listdir(dir):
        #print "x", dir, name
        path = os.path.join(dir, name)
        if name.endswith('.go'):
            if os.path.isfile(path) and "_enum" not in path and "_func" not in path and "_db" not in path:
                yield (dir, name)
        elif not "." in name:
            for d, f  in scan_dir_for_go_files(path):
                yield (d, f)

class StructPanel(wx.Panel):
    def __init__(self, parent, structName, memberDict):
        wx.Panel.__init__(self, parent=parent.nb, id=wx.ID_ANY)

        self.url = parent.url
        self.jsonDict = {}
        self.structName = structName
        self.structStateName = structName.rstrip('Config') + 'State'
        self.responseKeys = []
        self.currentFreeIndex = 0
        self.currGridSelection = None


        self.restTitle = wx.StaticText(self, label="RESTful Commands", pos=(50, 10))
        self.attrTitle = wx.StaticText(self, label="Create/Update Model Attributes", pos=(50, 80))
        self.getTitle = wx.StaticText(self, label="Event Log / Retrieve Info", pos=(450, 10))
        self.createTitle = wx.StaticText(self, label="Objects (Select Id for Delete/Update/Retrieve)", pos=(700, 10))

        # A multiline TextCtrl - This is here to show how the events work in this program, don't pay too much attention to it
        self.logger = wx.TextCtrl(self, pos=(450,30), size=(200,300), style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.myGrid = wx.grid.Grid(self, pos=(700,30), size=(300,300), name="Created Obj")
        # key id
        self.myGrid.CreateGrid(15, 2)
        self.myGrid.SetColLabelValue(0, "key")
        self.myGrid.SetColLabelValue(1, "id")
        self.Bind(wx.grid.EVT_GRID_CELL_LEFT_CLICK, self.OnCellLeftClick)


        # RESTful buttons
        self.button1 =wx.Button(self, label="Create", pos=(20, 30))
        self.Bind(wx.EVT_BUTTON, EvtSendDataOnClick(self), self.button1)

        self.button2 =wx.Button(self, label="Delete", pos=(120, 30))
        self.Bind(wx.EVT_BUTTON, EvtSendDeleteOnClick(self), self.button2)

        self.button3 =wx.Button(self, label="Update", pos=(220, 30))
        self.Bind(wx.EVT_BUTTON, EvtSendUpdateOnClick(self), self.button3)

        self.button4 =wx.Button(self, label="Retrieve State", pos=(320, 30))
        self.Bind(wx.EVT_BUTTON, EvtSendRetrieveOnClick(self), self.button3)


        # the edit control - one line version.

        self.memberDict = memberDict

        self.lblname = []
        self.editname = []
        i = 0
        pos = 20
        for name, argType in self.memberDict.iteritems():
            self.lblname.append(wx.StaticText(self, label=name, pos=(pos, 100+(i*60))))
            self.editname.append(wx.TextCtrl(self, value=argType, pos=(pos, 120+(i*60)), size=(100, -1), style=wx.TE_PROCESS_ENTER))
            self.Bind(wx.EVT_TEXT_ENTER, EvtTextHandler(self, name), self.editname[-1])
            self.Bind(wx.EVT_CHAR, self.EvtChar, self.editname[-1])
            i += 1
            if i % 5 == 0:
                pos += 140
                i = 0

    def OnCellLeftClick(self, event):
        self.currGridSelection = (event.GetRow(), event.GetCol(), self.myGrid.GetCellValue(event.GetRow(),event.GetCol()))
        self.logger.AppendText('EvtCellLeftClick: r(%s):c(%s):val(%s)\n' % self.currGridSelection)

    def EvtChar(self, event):
        self.logger.AppendText('EvtChar: %d\n' % event.GetKeyCode())
        event.Skip()


class ModelPanel(wx.Panel):
    def __init__(self, parent, fileStructTuple):
        wx.Panel.__init__(self, parent=parent, id=wx.ID_ANY)

        self.jsonDict = {}

        self.nb = wx.Notebook(self, wx.ID_ANY)
        self.url = parent.url

        # lets have a page for each struct within the model
        deletingComment = False
        foundStruct = False
        currentStruct = None
        goMemberTypeDict = {}
        (filename, structList) = fileStructTuple
        for path in GO_MODEL_BASE_PATH_LIST:
            try:
                with open(path+filename, "r") as f:
                    print 'processing', path+filename
                    for line in f.readlines():
                        if not deletingComment:
                            if "struct" in line:
                                lineSplit = line.split(" ")
                                currentStruct = lineSplit[1]
                                if currentStruct in structList:
                                    goMemberTypeDict[currentStruct] = {}
                                    foundStruct = True
                                    print 'found struct', currentStruct

                            elif "}" in line and foundStruct:
                                foundStruct = False
                                # create the various functions for db
                                self.nb.AddPage(StructPanel(self, currentStruct, goMemberTypeDict[currentStruct]), currentStruct)
                                print 'struct end'

                            # lets skip all blank lines
                            # skip comments
                            elif line == '\n' or \
                                "//" in line or \
                                "#" in line or \
                                "package" in line or \
                                    ("/*" in line and "*/" in line):
                                continue
                            elif "/*" in line:
                                deletingComment = True
                            elif foundStruct:  # found element in struct
                                # print "found element line", line
                                lineSplit = line.split(' ')
                                # print lineSplit
                                elemtype = lineSplit[-3].rstrip('\n') if 'KEY' in lineSplit[-1] else lineSplit[-1].rstrip('\n')

                                #print "elemtype:", lineSplit, elemtype
                                if elemtype.startswith("[]"):
                                    elemtype = elemtype.lstrip("[]")
                                    # lets make all list an unordered list
                                    nativetype = "LIST " + class_map[elemtype]["native_type"]
                                    goMemberTypeDict[currentStruct].update({lineSplit[0].lstrip(' ').rstrip(' ').lstrip('\t'):
                                                                            nativetype})
                                else:
                                    if elemtype in class_map.keys():
                                        goMemberTypeDict[currentStruct].update({lineSplit[0].lstrip(' ').rstrip(' ').lstrip('\t'):
                                                                                    class_map[elemtype]["native_type"]})

                        else:
                            if "*/" in line:
                                deletingComment = False
            except Exception as e:
                #print e
                continue

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.nb, 1, wx.ALL|wx.EXPAND, 5)
        self.SetSizer(sizer)
        '''
        # the combobox Control
        self.sampleList = ['friends', 'advertising', 'web search', 'Yellow Pages']
        self.lblhear = wx.StaticText(self, label="How did you hear from us ?", pos=(20, 90))
        self.edithear = wx.ComboBox(self, pos=(150, 90), size=(95, -1), choices=self.sampleList, style=wx.CB_DROPDOWN)
        self.Bind(wx.EVT_COMBOBOX, self.EvtComboBox, self.edithear)
        self.Bind(wx.EVT_TEXT, self.EvtText,self.edithear)

        # Checkbox
        self.insure = wx.CheckBox(self, label="Do you want Insured Shipment ?", pos=(20,180))
        self.Bind(wx.EVT_CHECKBOX, self.EvtCheckBox, self.insure)

        # Radio Boxes
        radioList = ['blue', 'red', 'yellow', 'orange', 'green', 'purple', 'navy blue', 'black', 'gray']
        rb = wx.RadioBox(self, label="What color would you like ?", pos=(20, 210), choices=radioList,  majorDimension=3,
                         style=wx.RA_SPECIFY_COLS)
        self.Bind(wx.EVT_RADIOBOX, self.EvtRadioBox, rb)
        '''
    def EvtRadioBox(self, event):
        self.logger.AppendText('EvtRadioBox: %d\n' % event.GetInt())
    def EvtComboBox(self, event):
        self.logger.AppendText('EvtComboBox: %s\n' % event.GetString())
    def OnClick(self,event):
        self.logger.AppendText(" Click on object with Id %d\n" %event.GetId())



    def EvtText(self, event):
        self.logger.AppendText('EvtText %s\n' % (event.GetString()))
    def EvtCheckBox(self, event):
        self.logger.AppendText('EvtCheckBox: %d\n' % event.Checked())


class RestSetupPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent=parent, id=wx.ID_ANY)

        self.url = parent.url
        self.urlTitle = wx.StaticText(self, label="URL", pos=(50, 10))

        # A multiline TextCtrl - This is here to show how the events work in this program, don't pay too much attention to it
        self.logger = wx.TextCtrl(self, pos=(450,30), size=(200,300), style=wx.TE_MULTILINE | wx.TE_READONLY)


        self.urlTextCtrl = wx.TextCtrl(self, value=LOCAL_HOST_URL, pos=(20, 30), size=(200, -1), style=wx.TE_PROCESS_ENTER)
        self.Bind(wx.EVT_TEXT_ENTER, EvtUrlTextHandler(self), self.urlTextCtrl)


class EvtUrlTextHandler(object):
    def __init__(self, parent):
        self.url = parent.url
        self.logger = parent.logger

    def __call__(self, event):
        self.url = event.GetString()
        self.logger.AppendText("URL set to %s\n" %(self.url,))


class EvtSendDataOnClick(object):
    def __init__(self, parent):
        self.parent = parent
        self.logger = parent.logger
        self.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    def __call__(self, event):


        jsonKeys = self.parent.jsonDict.keys()
        if len(self.parent.memberDict.keys()) == len(jsonKeys):
            key = "-".join([str(v) for k,v in self.parent.jsonDict.iteritems() if 'Key' in k])
            self.logger.AppendText(" Sending url %s/%s data to %d with key %s\n" %(self.parent.url,
                                                                                   self.parent.structName,
                                                                                   event.GetId(),
                                                                                   key))
            try:
                response = requests.post('%s/%s' % (self.parent.url, self.parent.structName), data=json.dumps(self.parent.jsonDict), headers=self.headers)
                self.logger.AppendText(" response %s\n" %(response.__dict__))
                # save the current id to the grid
                self.parent.myGrid.SetCellValue(0, self.parent.currentFreeIndex, key)
                self.parent.myGrid.SetCellValue(1, self.parent.currentFreeIndex, response.json()['_content'])
                self.parent.currentFreeIndex += 1
            except Exception as e:
                self.logger.AppendText("URL failed: %s" %(e, ))
        else:
            self.logger.AppendText(" Error missing values for full list [%s] provlist[%s] missing[%s]" %(jsonKeys, self.parent.memberDict, set(self.parent.memberDict).difference(jsonKeys)))

class EvtSendDeleteOnClick(object):
    def __init__(self, parent):
        self.parent = parent
        self.logger = parent.logger

    def __call__(self, event):
        self.logger.AppendText("TODO: Calling Delete for %s\n", self.parent.currGridSelection)
        # only process id
        if self.parent.currGridSelection is not None and \
           self.parent.currGridSelection[2] and \
           self.parent.currGridSelection[1] == 1:
            response = requests.delete('%s/%s/%s' % (self.parent.url, self.parent.structName, self.parent.currGridSelection))
            self.logger.AppendText(response)
            # clear the cell contents
            self.parent.myGrid.ClearSelection()
            #self.parent.myGrid.SetCellValue(self.parent.currGridSelection[0], self.parent.currGridSelection[1]-1, None)
            #self.parent.myGrid.SetCellValue(self.parent.currGridSelection[0], self.parent.currGridSelection[1], None)
            self.parent.currGridSelection = None
            # TODO sort grid

class EvtSendUpdateOnClick(object):
    def __init__(self, parent):
        self.parent = parent
        self.logger = parent.logger

    def __call__(self, event):
        self.logger.AppendText("TODO: Calling Update\n")
        requests.put('%s/%s' % (self.url, self.parent.structName), data= json.dumps(self.parent.jsonDict))

class EvtSendRetrieveOnClick(object):
    def __init__(self, parent):
        self.parent = parent
        self.logger = parent.logger

    def __call__(self, event):
        self.logger.AppendText("TODO: Calling Retrieve State\n")

class EvtTextHandler(object):
    def __init__(self, parent, memberName):
        self._memberName = memberName
        self.logger = parent.logger
        self.parent = parent

    def __call__(self, event):
        data = event.GetString()
        if data in class_bool_map.keys():
            print 'found boolean', data
            data = class_bool_map[data]
        elif data.isdigit():
            print 'found digit', data
            data = int(data)
        else:
            print 'found string', data

        self.parent.jsonDict.update({self._memberName : data})


        self.logger.AppendText('EvtText %s %s\n' % (self._memberName, data))



########################################################################
class SnaprouteModelNotebook(wx.Notebook):
    """
    Notebook class
    """

    #----------------------------------------------------------------------
    def __init__(self, parent):
        wx.Notebook.__init__(self, parent, id=wx.ID_ANY, style=
                             #wx.BK_DEFAULT
                             #wx.BK_TOP
                             #wx.BK_BOTTOM
                             wx.BK_LEFT
                             #wx.BK_RIGHT)
                             )

        self.url = "http://10.1.10.242:8080"

        # create panel which will be used to setup
        # the whitbox info.  URL, launch applications, etc
        self.AddPage(RestSetupPanel(self), "Restful Setup")

        goStructsList = []
        get_registered_structs_from_json(goStructsList)

        for (name, structList) in goStructsList:
            for path in GO_MODEL_BASE_PATH_LIST:
                for p,f in scan_dir_for_go_files(path):
                    if f.startswith('gen') or f == 'objects.go':
                        print p, f, structList
                        self.AddPage(ModelPanel(self, (f, structList)), f.lstrip('gen').rstrip('.go'))

        # Create the first tab and add it to the notebook
        #tabOne = NestedPanel(self)
        #self.AddPage(tabOne, "TabOne")

        # Show how to put an image on one of the notebook tabs,
        # first make the image list:
        #il = wx.ImageList(16, 16)
        #idx1 = il.Add(images.Smiles.GetBitmap())
        #self.AssignImageList(il)

        # now put an image on the first tab we just created:
        #self.SetPageImage(0, idx1)

        # Create and add the second tab
        #tabTwo = PanelOne(self)
        #self.AddPage(tabTwo, "TabTwo")

        # Create and add the third tab
        #self.AddPage(PanelOne(self), "TabThree")

        self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnPageChanged)
        self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGING, self.OnPageChanging)

    def OnPageChanged(self, event):
        old = event.GetOldSelection()
        new = event.GetSelection()
        sel = self.GetSelection()
        print 'OnPageChanged,  old:%d, new:%d, sel:%d\n' % (old, new, sel)
        event.Skip()

    def OnPageChanging(self, event):
        old = event.GetOldSelection()
        new = event.GetSelection()
        sel = self.GetSelection()
        print 'OnPageChanging, old:%d, new:%d, sel:%d\n' % (old, new, sel)
        event.Skip()


########################################################################
class RestfulFrame(wx.Frame):
    """
    Frame that holds all other widgets
    """

    #----------------------------------------------------------------------
    def __init__(self):
        """Constructor"""
        wx.Frame.__init__(self, None, wx.ID_ANY,
                          "Snaproute REST Model Tester",
                          size=(2000,600)
                          )

        panel = wx.Panel(self)

        notebook = SnaprouteModelNotebook(panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(notebook, 1, wx.ALL|wx.EXPAND, 5)
        panel.SetSizer(sizer)
        self.Layout()

        self.Show()

#----------------------------------------------------------------------
if __name__ == "__main__":
    app = wx.App()
    frame = RestfulFrame()
    app.MainLoop()
