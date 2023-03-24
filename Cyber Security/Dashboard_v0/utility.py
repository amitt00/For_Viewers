import pandas as pd
from sklearn import preprocessing


class DataProcessorIPINFO:
    def load_ipdata(self,filename):
        datainfo=pd.read_json(filename)
        dummy=[]
        for i in datainfo.values:
            ip=list(i[1].values())
            ip1=[i[0]]+ip
            dummy.append(ip1)
        datainfo=pd.DataFrame(dummy,columns=["IP","Country","country_code","isp","latitude","longitude","hostnames","org","domains"])


        datainfo=datainfo[~datainfo.latitude.isna()]
        datainfo.latitude=datainfo.latitude.astype(float)
        datainfo.longitude=datainfo.longitude.astype(float)
        datainfo=datainfo.fillna("No Record")
        datainfo=datainfo[datainfo.Country!="No Record"]
        self.dataipinfo=datainfo
        return datainfo
    
d=DataProcessorIPINFO()
ipinfo=d.load_ipdata("ipinfodb.json")
le = preprocessing.LabelEncoder()
ipinfo["CountryLE"]=le.fit_transform(ipinfo.Country)
