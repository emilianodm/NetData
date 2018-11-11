import test_snmp as snmp
#import sshutils as ssh
#import tnetutils as telnet
import re

ElementOids = {
    "Huawei" : {
        "CX600-X8A" : [
            {'Name' : "ifName", 'Oid' : "1.3.6.1.2.1.31.1.1.1.1.$index" },
            {'Name' : "ifDescr", 'Oid' : "1.3.6.1.2.1.31.1.1.1.18.$index"},
            {'Name' : "ifSessions", 'Oid' : "1.3.6.1.4.1.9.9.786.1.2.1.1.5.2.$index"},
            {'Name' : "ifOperStatus", 'Oid' : "1.3.6.1.2.1.2.2.1.8.$index"},
            {'Name' : "ifHCInOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.6.$index"},
            {'Name' : "ifHCOutOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.10.$index"},
            {'Name' : "ifHCInUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.7.$index"},
            {'Name' : "ifHCOutUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.11.$index"},
            {'Name' : "ifHCInMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.8.$index"},
            {'Name' : "ifHCOutMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.12.$index"},
            {'Name' : "ifHCInBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.9.$index"},
            {'Name' : "ifHCOutBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.13.$index"}
        ],
        "CX600-X16A" : [
            {'Name' : "ifName", 'Oid' : "1.3.6.1.2.1.31.1.1.1.1.$index" },
            {'Name' : "ifDescr", 'Oid' : "1.3.6.1.2.1.31.1.1.1.18.$index"},
            {'Name' : "ifSessions", 'Oid' : "1.3.6.1.4.1.9.9.786.1.2.1.1.5.2.$index"},
            {'Name' : "ifOperStatus", 'Oid' : "1.3.6.1.2.1.2.2.1.8.$index"},
            {'Name' : "ifHCInOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.6.$index"},
            {'Name' : "ifHCOutOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.10.$index"},
            {'Name' : "ifHCInUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.7.$index"},
            {'Name' : "ifHCOutUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.11.$index"},
            {'Name' : "ifHCInMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.8.$index"},
            {'Name' : "ifHCOutMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.12.$index"},
            {'Name' : "ifHCInBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.9.$index"},
            {'Name' : "ifHCOutBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.13.$index"}
        ],
        "CX600-X8" : [
            {'Name' : "ifName", 'Oid' : "1.3.6.1.2.1.31.1.1.1.1.$index" },
            {'Name' : "ifDescr", 'Oid' : "1.3.6.1.2.1.31.1.1.1.18.$index"},
            {'Name' : "ifSessions", 'Oid' : "1.3.6.1.4.1.9.9.786.1.2.1.1.5.2.$index"},
            {'Name' : "ifOperStatus", 'Oid' : "1.3.6.1.2.1.2.2.1.8.$index"},
            {'Name' : "ifHCInOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.6.$index"},
            {'Name' : "ifHCOutOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.10.$index"},
            {'Name' : "ifHCInUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.7.$index"},
            {'Name' : "ifHCOutUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.11.$index"},
            {'Name' : "ifHCInMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.8.$index"},
            {'Name' : "ifHCOutMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.12.$index"},
            {'Name' : "ifHCInBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.9.$index"},
            {'Name' : "ifHCOutBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.13.$index"}
        ],
        "CX600-X16" : [
            {'Name' : "ifName", 'Oid' : "1.3.6.1.2.1.31.1.1.1.1.$index" },
            {'Name' : "ifDescr", 'Oid' : "1.3.6.1.2.1.31.1.1.1.18.$index"},
            {'Name' : "ifSessions", 'Oid' : "1.3.6.1.4.1.9.9.786.1.2.1.1.5.2.$index"},
            {'Name' : "ifOperStatus", 'Oid' : "1.3.6.1.2.1.2.2.1.8.$index"},
            {'Name' : "ifHCInOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.6.$index"},
            {'Name' : "ifHCOutOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.10.$index"},
            {'Name' : "ifHCInUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.7.$index"},
            {'Name' : "ifHCOutUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.11.$index"},
            {'Name' : "ifHCInMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.8.$index"},
            {'Name' : "ifHCOutMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.12.$index"},
            {'Name' : "ifHCInBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.9.$index"},
            {'Name' : "ifHCOutBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.13.$index"}
        ]
    },
    "Cisco" : {
        "ASR9K" : [
            {'Name' : "ifName", 'Oid' : "1.3.6.1.2.1.31.1.1.1.1.$index" },
            {'Name' : "ifDescr", 'Oid' : "1.3.6.1.2.1.31.1.1.1.18.$index"},
            {'Name' : "ifSessions", 'Oid' : "1.3.6.1.4.1.9.9.786.1.2.1.1.5.2.$index"},
            {'Name' : "ifOperStatus", 'Oid' : "1.3.6.1.2.1.2.2.1.8.$index"},
            {'Name' : "ifHCInOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.6.$index"},
            {'Name' : "ifHCOutOctets", 'Oid' : "1.3.6.1.2.1.31.1.1.1.10.$index"},
            {'Name' : "ifHCInUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.7.$index"},
            {'Name' : "ifHCOutUcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.11.$index"},
            {'Name' : "ifHCInMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.8.$index"},
            {'Name' : "ifHCOutMulticastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.12.$index"},
            {'Name' : "ifHCInBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.9.$index"},
            {'Name' : "ifHCOutBroadcastPkts", 'Oid' : "1.3.6.1.2.1.31.1.1.1.13.$index"}
        ],
    }
}


class Polling_Entity(object):
    def __init__(self,ElementName):
        #Input Parameters
        self.ElementName = ElementName

        #Relevo el SysDescr del elemnto para definir Vendor, modelo y version
        #iso.3.6.1.2.1.1.1.0 = sysDescr
        #retorna dict( Result : value, Type: Typeof)

        try:
            #--------------------------------------------------------------------------------------------
            oid_ElementSysDescr = "iso.3.6.1.2.1.1.1.0"
            self.ElementSysDescr = snmp.get(ElementName,oid_ElementSysDescr)

            ElementVendors = ["Huawei", "Cisco"]
            ElementModels = { 
                "Huawei" : ["CX600-X8A","CX600-X16A","CX600-X8","CX600-X16"], 
                "Cisco"  : ["ASR9K"] 
            }

            #--------------------------------------------------------------------------------------------
            for Vendor in ElementVendors:
                if Vendor in self.ElementSysDescr['Result'] and self.ElementSysDescr['Type'] == "STRING" :
                    self.ElementVendor = Vendor
                    break

            try:
                self.ElementVendor
            except NameError:
                raise ElementVendorNotValidError

            #--------------------------------------------------------------------------------------------
            for Model in ElementModels[self.ElementVendor]:
                if Model in self.ElementSysDescr['Result'] and self.ElementSysDescr['Type'] == "STRING" :
                    self.ElementModel = Model
                    break

            try:
                self.ElementModel
            except NameError:
                raise ElementModelNotValidError

        except:
            raise

        #--------------------------------------------------------------------------------------------

        #Search for index and descriptions
        #1.3.6.1.2.1.31.1.1.1.18 = ifDescr
        #retorna list of dict ( Index : value , Result: value , Type: TypeOf)

        try:
            oid_ElementIfDescr = "iso.3.6.1.2.1.1.1.0"
            self.ElementIfDescr = snmp.walk(ElementName, oid_ElementIfDescr)

            self.ElementIfDescrValid = {}

            #Pattern for description match ('DATOS' AND 'L3')
            try:
                IfDescrPattern = re.compile(".*?DATOS\b.*?L3\b")
            except:
                raise IfDescrPatternError
            

            for Value in self.ElementIfDescr :
                #Si matchea con el pattern
                if IfDescrPattern.match(Value['Result']) == True :
                    self.ElementIfDescrValid.append(Value)

        except:
            raise

        #--------------------------------------------------------------------------------------------
    
    def GetInformation(self):
        try:
            GetInformationResult = {}
            GetValueResult = {}
            GetOidResult = {}

            for Item in self.ElementIfDescrValid :

                GetValueResult.clear()

                #Static append of descr and index
                GetOidResult.clear()
                GetOidResult['Name']='ifIndex'
                GetOidResult['Value']=Item['Index']
                GetValueResult.append(GetOidResult)

                GetOidResult.clear()
                GetOidResult['Name']='ifDescr'
                GetOidResult['Value']=Item['Result']
                GetValueResult.append(GetOidResult)

                #Dynamic append of the other values
                for OidInfo in ElementOids[self.ElementVendor][self.ElementModel] :
                    #snmpget
                    #--------- Value = xxxxxxxxxxxxx Item.
                    OidValue = OidInfo['Oid'].replace("$index",Item['Index'])
                    Value = snmp.get(self.ElementName,OidValue)

                    GetOidResult.clear()
                    GetOidResult['Name']=OidInfo['Name']
                    GetOidResult['Value']=Value['Result']
                    
                    GetValueResult.append(GetOidResult)

                #Append all the information of the current index
                GetInformationResult.append(GetValueResult)

            #Return all the information
            return GetInformationResult

        except:
            raise