import pickle # used to save the model for further testing and use
import csv #python standard for csv work
import pyshark # tshark wrapper used to capture and parse packets
import time #allows for time be used
import datetime #allows for dates to be used
import pandas # data handler for input into Aritificial neural network
from timeit import default_timer as timer
from sklearn.preprocessing import LabelEncoder

def LiveLabelEncoding(data): # same as LabelEncoding(), but use for realtime
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))  
    print(columnsToEncode)
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
            #print(data[feature])
        except:
            print ('error ' + feature)
    return data

def get_ip_layer_name(pkt): #allows the program to differentiate between ipv4 and ipv6, needed for correct parsing of packets
    for layer in pkt.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6
allowed_IP = []
input_file = input('Enter file name to test : ')
data = pandas.read_csv(input_file, delimiter=',') # reads CSV
data = LiveLabelEncoding(data)
print("Processing Data", "\n")
print(data)
X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port','Packet Length', 'Packets/Time' ]] # Data used to train
print(type(X))


from sklearn.preprocessing import StandardScaler
#scaler = StandardScaler()
#scaler.fit(X)
#X = scaler.transform(X)

modelname = input('Enter Model to load : ')
loaded_model = pickle.load(open(modelname, 'rb')) # loads model
#print("Model Coeffcients ", loaded_model.coefs_) # load model coefs
lmlp = loaded_model
'''
predictions = lmlp.predict(X) # preditcions made by model

hostile = 0 # this block counts how many 'hostile' packets have been predicted by the model
safe = 0
for check in predictions:
    if check == 1: # change to 0 to force ddos attack
        hostile += 1
    else:
        safe += 1
print("Safe Packets: ", safe)
print("Possible Hostile Packets: ", hostile)
print(100 * hostile/(safe + hostile))
print()
'''
iface = input("Please select interface: ")
cap = pyshark.LiveCapture(interface= iface)
cap.sniff_continuously(packet_count=None)


#Write this data to a file
start_time = time.time()
start = timer()
i=0
df = pandas.DataFrame(columns=['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port','Packet Length', 'Packets/Time'])
for pkt in cap:
    
    end = timer()
    try:
        if pkt.highest_layer != 'ARP':
            print("Packets Collected:", i)
            if pkt.highest_layer != 'ARP':
                ip = None
                ip_layer = get_ip_layer_name(pkt)
                if ip_layer == 4:
                    ip = pkt.ip
                    #ipv = 0 # target test
                    if pkt.transport_layer == None:
                        transport_layer = 'None'
                    else:
                        transport_layer = pkt.transport_layer
                elif ip_layer == 6:
                    ip = pkt.ipv6
                    #ipv = 1 # target test
                try:
                    if ip.src not in allowed_IP:
                        ipcat = 1
                    else:
                        ipcat = 0
                    df.loc[len(df)] = [pkt.highest_layer, transport_layer, ipcat, ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport,pkt.length, i/(time.time() - start_time)]
                    print ("Time: ", time.time() - start_time)
                    i += 1
                except AttributeError:
                    if ip.src not in allowed_IP:
                        ipcat = 1
                    else:
                        ipcat = 0
                    df.loc[len(df)] = [pkt.highest_layer, transport_layer, ipcat, ip.dst, 0, 0, pkt.length, i/(time.time() - start_time)]
                    print ("Time: ", time.time() - start_time)
                    i += 1
            else:
                if pkt.arp.src_proto_ipv4 not in allowed_IP:
                    ipcat = 1
                else:
                    ipcat = 0
                arp = pkt.arp
                df.loc[len(df)] = [pkt.highest_layer, transport_layer, ipcat, arp.dst_proto_ipv4, 0, 0, pkt.length, i/(time.time() - start_time)]
                print ("Time: ", time.time() - start_time)
                i += 1
        
        #print(df.size)
        
        lmlp.predict(df.to_string(index=False).tail(1))
        
        hostile = 0 # this block counts how many 'hostile' packets have been predicted by the model
        safe = 0
        for check in predictions:
        	if check == 1: # change to 0 to force ddos attack
        		#hostile += 1
        		print('Attack')
        		exit()
        	else:
        		safe+=1
        	#print("Safe Packets: ", safe)
        	#print("Possible Hostile Packets: ", hostile)
        	#print(100 * hostile/(safe + hostile))
        	#print()
        
    except (UnboundLocalError, AttributeError) as e:
        pass








