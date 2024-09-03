import yaml
import os

class PortConfig:
    """ 
        Singleton class that parses config .yaml file for port configuration
        provided in a human readable format 
    """
    
    # you may want to add here other values
    defaults = {
        "speed" : "100G",
        "fec" : "rs",
        "auto_neg" : "default",
        "conn_id" : 0,
        "chnl_id" : 0,
    }

    # insead of being static this could be read from $PORT_HDL_INFO table
    # (Front-panel port to dev port lookup table) (here we added the recirculation ports as well)
    frontport2devport = {
        "R/0" :   68,
        "R/1" :  196,
        "1/0" :  132,
        "1/1" :  133,
        "1/2" :  134,
        "1/3" :  135,
        "2/0" :  140,
        "2/1" :  141,
        "2/2" :  142,
        "2/3" :  143,
        "3/0" :  148,
        "3/1" :  149,
        "3/2" :  150,
        "3/3" :  151,
        "4/0" :  156,
        "4/1" :  157,
        "4/2" :  158,
        "4/3" :  159,
        "5/0" :  164,
        "5/1" :  165,
        "5/2" :  166,
        "5/3" :  167,
        "6/0" :  172,
        "6/1" :  173,
        "6/2" :  174,
        "6/3" :  175,
        "7/0" :  180,
        "7/1" :  181,
        "7/2" :  182,
        "7/3" :  183,
        "8/0" :  188,
        "8/1" :  189,
        "8/2" :  190,
        "8/3" :  191,
        "9/0" :   56,
        "9/1" :   57,
        "9/2" :   58,
        "9/3" :   59,
        "10/0" :  48,
        "10/1" :  49,
        "10/2" :  50,
        "10/3" :  51,
        "11/0" :  40,
        "11/1" :  41,
        "11/2" :  42,
        "11/3" :  43,
        "12/0" :  32,
        "12/1" :  33,
        "12/2" :  34,
        "12/3" :  35,
        "13/0" :  24,
        "13/1" :  25,
        "13/2" :  26,
        "13/3" :  27,
        "14/0" :  16,
        "14/1" :  17,
        "14/2" :  18,
        "14/3" :  19,
        "15/0" :   8,
        "15/1" :   9,
        "15/2" :  10,
        "15/3" :  11,
        "16/0" :   0,
        "16/1" :   1,
        "16/2" :   2,
        "16/3" :   3,
        "17/0" :   4,
        "17/1" :   5,
        "17/2" :   6,
        "17/3" :   7,
        "18/0" :  12,
        "18/1" :  13,
        "18/2" :  14,
        "18/3" :  15,
        "19/0" :  20,
        "19/1" :  21,
        "19/2" :  22,
        "19/3" :  23,
        "20/0" :  28,
        "20/1" :  29,
        "20/2" :  30,
        "20/3" :  31,
        "21/0" :  36,
        "21/1" :  37,
        "21/2" :  38,
        "21/3" :  39,
        "22/0" :  44,
        "22/1" :  45,
        "22/2" :  46,
        "22/3" :  47,
        "23/0" :  52,
        "23/1" :  53,
        "23/2" :  54,
        "23/3" :  55,
        "24/0" :  60,
        "24/1" :  61,
        "24/2" :  62,
        "24/3" :  63,
        "25/0" : 184,
        "25/1" : 185,
        "25/2" : 186,
        "25/3" : 187,
        "26/0" : 176,
        "26/1" : 177,
        "26/2" : 178,
        "26/3" : 179,
        "27/0" : 168,
        "27/1" : 169,
        "27/2" : 170,
        "27/3" : 171,
        "28/0" : 160,
        "28/1" : 161,
        "28/2" : 162,
        "28/3" : 163,
        "29/0" : 144,
        "29/1" : 145,
        "29/2" : 146,
        "29/3" : 147,
        "30/0" : 152,
        "30/1" : 153,
        "30/2" : 154,
        "30/3" : 155,
        "31/0" : 128,
        "31/1" : 129,
        "31/2" : 130,
        "31/3" : 131,
        "32/0" : 136,
        "32/1" : 137,
        "32/2" : 138,
        "32/3" : 139,
        "33/0" :  64,
        "33/1" :  65,
        "33/2" :  66,
        "33/3" :  67,
    }

    interfaces = None

    def __init__(self) -> None:
        # one-line singleton
        PortConfig.__new__ = lambda _: self
        
        filename = os.path.join(os.path.dirname(__file__), 'ports.yaml')
        with open(filename) as f:
            self.interfaces = yaml.safe_load(f)
    

    def port_param_get(self, port, param):        
        try:
            c = self.interfaces[port]
        except KeyError:
            print("Error: port %s not found in ports.yaml" % port)
            quit(1)

        try:
            c['devport'] = self.frontport2devport[port]
            return c[param]
        except KeyError:
            return self.defaults[param]


# use this outside of the module (potentially could add here other "global" configurations)
config = {
    'interfaces' : PortConfig().interfaces
}


class PortInfo:
    """ 
        Returns values for port configuration to use in the Tofino BFRT tables. 
        Reads parameters from the ports.yaml file and returns the values for the port configuration. 
    """
    def __init__(self, front_port):
        self.front_port = front_port

        # converts from devport to front panel port (R/0 and R/1 are special values for recirculation ports)
        self.devPort = PortConfig().port_param_get(front_port, "devport")

        self.speed = str(PortConfig().port_param_get(front_port, 'speed')) # can try to change the value in the ports.json file and see if here we get different values
        self.fec = str(PortConfig().port_param_get(front_port, 'fec'))
        auto_neg = PortConfig().port_param_get(front_port, 'auto_neg')
        if auto_neg is not None:
            self.autoNeg = str(auto_neg)
        conn_id = PortConfig().port_param_get(front_port, 'conn_id')
        if conn_id is not None:
            self.conn_id = int(conn_id)
        else:
            print("Error: port %s has no conn_id defined. Use 'bf-sde>pm show' to get the mapping" % front_port)
            assert (0)
        chnl_id = PortConfig().port_param_get(front_port, 'chnl_id')
        if chnl_id is not None:
            self.chnl_id = int(chnl_id)
        else:
            print("Error: port %s has no chnl_id defined. Use 'bf-sde>pm show' to get the mapping" % front_port)
            assert (0)
        

    def getDevPort(self):
        return self.devPort

    def getSpeed(self):
        return {
            "10G": "BF_SPEED_10G",
            "25G": "BF_SPEED_25G",
            "40G": "BF_SPEED_40G",
            "40G_NB": "BF_SPEED_40G_NB",
            "50G": "BF_SPEED_50G",
            "100G": "BF_SPEED_100G",

            "200G": "BF_SPEED_200G",
            "400G": "BF_SPEED_400G",
            "40G_R2": "BF_SPEED_40G_R2"
        }.get(self.speed.upper(), "BF_SPEED_NONE")

    def getFec(self):
        return {
            "none": "BF_FEC_TYP_NONE",
            "rs": "BF_FEC_TYP_REED_SOLOMON",
            "fc": "BF_FEC_TYP_FIRECODE",
        }.get(self.fec, "BF_FEC_TYP_NONE")

    def getAutoNeg(self):
        return {
            "default": "PM_AN_DEFAULT",
            "enable": "PM_AN_FORCE_ENABLE",
            "disable": "PM_AN_FORCE_DISABLE"
        }.get(self.autoNeg, "PM_AN_DEFAULT")

    def getConnId(self):
        return self.conn_id

    def getChnlId(self):
        return self.chnl_id

    def getName(self):
        return "%d/%d" % (self.conn_id, self.chnl_id)

    def getDevPort(self):
        return self.devPort


if __name__ == "__main__":

    #print(PortInfo("2/0").getDevPort())
    #print(PortInfo("2/0").getSpeed())

    a = PortConfig()
    b = PortConfig()
    c = PortConfig()
    print(a,b)
