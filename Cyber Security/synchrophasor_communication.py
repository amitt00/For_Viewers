## After identifying the PDC using findhost.py ,
## This script Establishes connection with PMU in the network by scanning all ports 

#Importing Libraries 
#############
from crccheck.crc import Crc16CcittFalse, CrcXmodem
from bitarray import bitarray
from datetime import datetime
import array
import socket
import struct
import time
import matplotlib.pyplot as plt
#############Exit function

#Initialisation of few  Variables
#########
cmd=5                            
y3=0
temp=0
data=0
ieeeport=[]
portlist=[]
ProbableIDC=0
#Taking user input variables 


#print('Enter idcode:')
#idc=int(input())
idc=43
#print('Enter IP:')
dst_host="192.168.2.225"
#dst_host=input()
#print('Port range:Start')
#a=int(input())
#print('port range:Stop')
#b=int(input())
dst_port=list(range(1000,65535)) 
##########

#Features of command frame to be used later
#############
def soc():                                #SOC
   soc1=int(time.time()) 
   return(soc1)
def fracsec():                            #soc->fracsec
   frac=datetime.now()
   fracs=(frac.microsecond)+251658240
   return(fracs) 
def get_crc(frame):                       #CRC
   crc_p=Crc16CcittFalse.calc(frame)
   return (int(crc_p)).to_bytes(2, byteorder='big')
##############

#Creating Command frame to be sent in packet  Folowing IEEE Standard
######################
def pac(cmdp,idco):
   packe= struct.pack(
         '!HHHIIH',
         43585,          # Sync
         18,             # framesize
         idco,           # idcode
         soc(),          # soc
         fracsec(),      # fracsec
         cmdp            # cmd
                   )
   chk=get_crc(bytearray(packe))
   pacet1=packe+chk
   return(pacet1)
######################


#Partially decoding of Config frame recieved(if recieved)
############################
def frame_versize(data,port,db1):
    y=int(data[0])-43520
    y2=0
    if y==17 or y==18:
        print ('###Header frame recieved from port',port)
        y2=3
    if y==33 or y==34 or y==49 or y==50: 
        print ('###Configuration frame recieved from port',port)                 #Type of frame recieved
        y2=1
    if y==1 or y==2:
        print ('###Data frame recieved from port',port)
        print(db1.hex())
        y2=2
    if y%2==0:
        print ('##Following IEEE 2011 standard')
    else:
        print ('##Following IEEE 2005 standard of size (in bytes):',int(data[1]))     #Size and Standard
    return(y2)
#############################

#Fully Unpacking Recieved Configuration Frame if frame_versize worked fine
###############################
def rCFGf(d,port) :
  num_pmu=struct.unpack('>H',d[18:20])
  station_name=list(struct.unpack('>16s',d[20:36]))                      #Station Name
  pri={'Station Name':(str(station_name[0]).split('b',1)[1])}
  PMU_ID,FORMAT,PHNMR,ANNMR,DGNMR=struct.unpack('>HHHHH',d[36:46])       #PMU_ID,FORMAT,PHNMR,ANNMR,DGNMR
  pt={'NUM_PMU':int(num_pmu[0]),'PMU_ID':PMU_ID ,'FORMAT': format(FORMAT,'08b'), 'PHNMR':PHNMR,'ANNMR':ANNMR,'DGNMR':DGNMR} 
  ieeeport.append(port)
  try:
     t=16*(  (ANNMR+PHNMR)  + 16*(DGNMR)    )
     CHname=list(struct.iter_unpack('>16s',d[46:46+t]))                        #t=46+(16*[(ANNMR+PHNMR)+16*(DGNMR)]) 
     CHname1=list((((str(CHname[i]).replace('\\x00','')).split('b')[1]).split(',)')[0]) for i in range(len(CHname)))
     print('\nCHNAM List:',CHname1,sep = "\n")                                #Iterating in pack of 16 Channel,Name
     P=list(struct.iter_unpack('>I',d[t:t+(4*(ANNMR+PHNMR+DGNMR))]))
     P = list([i[0] for i in P])
     rA=t+(4*(ANNMR+PHNMR+DGNMR))
     P=list(hex(P[i]) for i in range(len(P)) )
     pt1={'PHUNIT':P[0:PHNMR],'ANUNIT':P[PHNMR:(ANNMR+PHNMR)],'DIGUNIT':P[(ANNMR+PHNMR):(ANNMR+PHNMR+DGNMR)]}
     FNOM,CFGCNT=struct.unpack('>HH',d[rA:(rA+4)])
     z2={'FNOM':FNOM,'CFGCNT':CFGCNT}
     z1={**pt,**pt1}
     z0 = {**z1, **z2}
     DATA_RATE={'DATA_RATE':(struct.unpack('>H',d[-4:-2]))}
     z={**z0, **DATA_RATE}
     Z={**pri, **z}
     for ParameTer, vaLue in Z.items():
        print(f'{ParameTer} -->> {vaLue}') 
  except:
     print('\n',pri | pt)
     print("Port Follows IEEE Protocol::Error in Decoding config frame rcvd:: struct_unpack.Error")  
  return(PHNMR,FORMAT)
##############################################

####################################
def colour(x):
    if x==60.4:
       return('red')
    else:
       return('blue')
#Tranmission(send/recv):If IEEE port 

#Connecting with each port in Port Range to check for IEEE/Open Ports
########################################################
def Main(dst_port,dst_host,idc):
  for i in dst_port:
      port=i
      try:  
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)  
          s.settimeout(105)
          s.bind(('',(4444+i)))
          s.connect((dst_host, port))
          portlist.append(port)
          print("ACK/SYN Recieved from Open Port:",port)
          print("Open port:",port,"\n")
          s.sendto(pac(5,idc),(dst_host,port))
          db=s.recv(4096)
          turnon=pac(2,idc)
          turnoff=pac(1,idc)
          if db!=0:
                unpacked=struct.unpack('>HHH',db[0:6])
                if int(db[0])==170:
                   if db[5]!=idc:
                     print("\nMaybe the correct ID-Code is :",db[5],":Try Again\n")
                     temp=1
                   frame_versize(unpacked,port,db)
                   phnmrNum,format=rCFGf(db,port)
                   print('Turn on data stream for time(in sec):')
                   t=int(input())
                   
                   plt.rcParams['animation.html']='jshtml'
                   fig=plt.figure()
                   ax=fig.add_subplot(111)
                   fig.show()

                   s.sendto(turnon,(dst_host,port))
                   print("Command to Turn Transmission on,Sent:")
                   data_buffer=''
                   start_time=time.time()  
                   try:
                     count=0
                     xt=[]
                     freq=[]
                     while True:                                      #Data Recieve start         
                          count=count+1
                          dsa=s.recv(16)
                          s.settimeout(25)
                          if dsa==0:
                             print("Some error in stable communication")
                          if len(dsa)<16:
                             data_buffer += dsa.hex()
                             print("Packet Count:",count)
                             #print(data_buffer,end='\r')
                             data_buffer=bytearray.fromhex(data_buffer) 
                             print(format)                         
                             #Distinguish and unpack:Format integer/floating point
                             if format>=8:
                                FREQ,flt=struct.unpack('!f', data_buffer[phnmrNum*8+16:phnmrNum*8+20])
 #                               recvunpack(data_buffer,format)
                             else:
                                FREQ,intgr=struct.unpack('!H', data_buffer[phnmrNum*4+16:phnmrNum*4+18])
#                                recvunpack(data_buffer,format)
                             
                            #Graph elements
                             print("Freq in recvD Packet from PMU:=",(FREQ[0]/1000)+60,"hz\n")
                            # print("Packet_count=",count,"\n",FREQ[0],end='\r')
                             freq=freq+[(FREQ[0]/1000)+60]
                             xt=xt+[count]
                             time.sleep(0.01)
                             #Real time Plot
                             if count>10:
                                if float((FREQ[0]/1000)+60)>60.06 :
                                   plt.plot(xt,freq,color='g', linestyle='dashed', markersize=12)
                                else:
                                   plt.plot(xt,freq,color='b', linestyle='dashed')
                                #ax.set_xlim(left=count-10,right=count+10)#To see better graph
                                fig.canvas.draw()
                                time.sleep(0.1)
                                plt.savefig("output.png")
                             data_buffer=''                            #Empty buffer,to recv new packet
                          else:
                             data_buffer +=dsa.hex()
                          if time.time()-start_time>t:
                             s.sendto((turnoff),(dst_host,port))
                             s.close()
                             print("Completed !! Moving to next port in input 'Port range'")
                             break
                   except:
                     if dsa==0:
                       print("No data Stream Rcvd")
                       s.close()
          else :
             print("No reply Recieved for Command frme sent on this port")
             s.close()
      except socket.error as err:
            if idc==1000: 
              print("Closed Port\n")
########################################################


##To start the scan
Main(dst_port,dst_host,idc)
#To summarise the scan
print("\nOpen Ports in range:",dst_port[0],":",dst_port[-1]," are:",portlist)
print("Ports Following IEEE protocols are:>",ieeeport,"\n")
