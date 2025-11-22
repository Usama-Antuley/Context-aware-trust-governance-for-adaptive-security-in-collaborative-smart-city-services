# Presentation of Programmable Script

# 1. Key Managment Module
1. **This Bash script generates multiple pairs of public-private keys and their corresponding hash values using OpenSSL commands For Interoperable Serivces,SDN controller, and the Client Node and Store in the Security.JSON File**
2. **Initially We Generate more then 50 Keypairs in Each client Machine**
3. **Create three different Key Folder repositiory i.e ECC-128 ,ECC-192,ECC-256**
4. **For ECC-192 use (prime192v1) and for use (prime256v1)**
#!/bin/bash

 `  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 ` 

` do`

` echo "Keys are Successfull generated " `

`openssl ecparam -name prime128v1 -genkey -noout -out private-key$i.pem > /home/ubuntu/Desktop/Shahbaz_Final_Project/Ada-Framework-Shahbaz1/01-GetStarted/Keys/keto$i.key
`

`openssl ec -in private-key$i.pem -pubout -out public-key$i.pem
openssl dgst -sha256 -binary private-key$i.pem > /home/ubuntu/Desktop/Shahbaz_Final_Project/Ada-Framework-Shahbaz1/01-GetStarted/Keys/hash$i.txt` 

` done `

`echo "}" >> security.json`

# 2. Service Managment Module
1. **Service management append ServiceSecurity.JSON File with trust option**
2. **The Abstractmote.Java is implemented in Java Platform working as client nodes of smart services that uses this file to update the trust value by fetching the vlaue from blockchain**
3. **We are using Filling inorder to integrate python code with Java Plateform**

```python

import json
import os
import hashlib
import multichain
from datetime import datetime
data1=[]
data2=[]
#######################################data1, data2.....added accordinlinh###############################
def encode_json(data):
    return json.dumps(data, indent=4)

def decode_json(json_data):
    return json.loads(json_data)

# Check if the file exists, and if so, read the existing data
if os.path.exists("/home/ubuntu/Desktop/Shahbaz_Final_Project/LocalContract/ServiceSecurity.json"):
    with open("/home/ubuntu/Desktop/Shahbaz_Final_Project/LocalContract/ServiceSecurity.json", "r") as f:
        data1= decode_json(f.read())
        print('Yes')
        
else:
    SensorContract1 = []
    


def ServiceManagement():

	while True:
	    breakstatement = input("Enter commit For Rule For Service ad : ")
	    if not breakstatement=="commit":
	        break
	    now = datetime.now()
	    current_time = now.strftime("%H:%M:%S")   
	    data1.append({
	        "Serviceid":"Service1",
	        "Contract": "Local",
	        "LocalRuleHash":hash1,
	        "Servicerthreshould":0.0	,
	        "PreviousTrust":0,
	        "ServiceTrust": 0.0,
	        "Role":"Admin",
	        "Authorization":["Create","Add","delete","Display"],
                "Role1":"User",
	        "Authorization":["display"],
	         "Time":current_time        
  	        
	           })
    
    
	    data2.append({
	        "LocalpolicyHash":hash2,
	        "Subject":"Service1",
	        "object":"Service2",
	        "CollaborativeServiceTrust":0.0,
	        "CollaborativeServicePTrust":0.0,
	        "CollaborativeServiceCTrust":0.0,
	        "Time":current_time         
	    })


	    data3.append({
	        "Serviceid":"Service2",
	        "Contract": "Local",
	        "LocalRuleHash":hash1,
	        "Servicerthreshould":0.0,
	        "PreviousTrust":0,
	        "ServiceTrust": 0.0,
	        "Role":"Admin",
	        "Authorization":["Create","Add","delete","Display"],
                "Role1":"User",
	        "Authorization":["display"],
  	        "Time":current_time
	           })
    
    
	    data4.append({
	        "LocalpolicyHash":hash2,
	        "Subject":"Service1",
	        "object":"Service2",
	        "CollaborativeServiceTrust":0.0,
	        "CollaborativeServicePTrust":0.0,
	        "CollaborativeServiceCTrust":0.0,
	        "Time":current_time         
	    })
```

# 3.Rule Engine and Policy engine Contract

1. **The rule engine is responsible for generating security rules, both local and global, based on the dynamic security
    requirements of smart services during collaborative tasks in interoperability scenarios in Blockchains**

```python

	#######################################Store rule in Multichain Application-1################
	rpcuser = "multichainrpc"
	rpcpassword = "3yCd7Ah7KC9rAUHrKNM694Lpq15dAPT7cJ6sgvPUKg9y"
	rpchost = "127.0.0.1"
	rpcport = "2652"
	chainname = "server"

	mc=multichain.MultiChainClient(rpchost, rpcport, rpcuser, rpcpassword)

	#print(mc.getinfo())
	txid1 = mc.create('stream', 'Localrule', True) # open to all to write
	
	#result = mc.getstreaminfo('Localrule')
	#result = mc.liststreams() # all streams


	#result = mc.liststreams('LocalRule') # one specific stream
	txid1 = mc.publish('LocalRule', 'key1', {'json' : {
	        "Serviceid":"Service1",
	        "Contract": "Local",
	        "LocalRuleHash":hash1,
	        "Servicerthreshould":0.1,
	        "PreviousTrust":0,
	        "ServiceTrust": 0.0,
	        "Service Value":0.0,
	        "Time":current_time         
	           }}) # JSON data
	mc.subscribe('LocalRule') 


	# one asset or stream
	#result = mc.liststreamitems('LocalRule')
	#result = mc.liststreamkeys('LocalRule') # all keys in stream
	#result = mc.liststreamkeys('LocalRule', 'key1')
	#result = mc.getstreamkeysummary('LocalRule', 'key1', 'jsonobjectmerge')
	result = mc.liststreamkeyitems('LocalRule', 'key1',False,1)

	#print(result)
	txid12 = mc.publish('LocalServiceAgreement', 'key1', {'json' : {
	        "TransactionalHash":txid1        
	           }}) # JSON data
	mc.subscribe('LocalServiceAgreement') 


	#######################################Store policies in Multichain################

	txid2 = mc.create('stream', 'LocalPolicies', True) # open to all to write

	#result = mc.getstreaminfo('Localrule')
	#result = mc.liststreams() # all streams


	#result = mc.liststreams('LocalRule') # one specific stream
	txid2 = mc.publish('LocalPolicies', 'key1', {'json' : {
	        "Serviceid":"Service1",  
	        "LocalpolicyHash":hash2,
	        "Subject":"Application",
	        "object":"School",
	        "CollaborativeServiceTrust":0.1,
	        "CollaborativeServicePTrust":0.0,
	        "CollaborativeServiceCTrust":0.0,
	        	        "Time":current_time                  
	    }}) # JSON data
	mc.subscribe('LocalPolicies') # one asset or stream
	#result = mc.liststreamitems('LocalRule')
	#result = mc.liststreamkeys('LocalRule') # all keys in stream
	#result = mc.liststreamkeys('LocalRule', 'key1')

	###################################SAmple Code inorder to Search the ItemFrom the Blockchain#######
	import json
	result1 = mc.liststreamkeyitems('LocalPolicies', 'key1',False,1)

	#print(result)


	#my_dict = {}  # create an empty dictionary

	# add key-value pairs to the dictionary

	#my_dict['txid'] = result[0]['txid']
	#my_dict['publisherid'] = result[0]['publishers']
	#print(my_dict)  # {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}

	########################Adaptive Security Engine Recieve Security Tokens for Rule and Policy -1##############################
	
	with open("/home/ubuntu/Desktop/Shahbaz_Final_Project/Application/Application.txt", "r") as f:
	    print("Security Contract For Service1")
	    data = f.read()    
	    data32 =json.loads(data)
	    ###Key Noticed result[0] only extract the Blockchain variable such as txid ,confirmation,publisherid not Application data
	data32['BLockchainLocalRule-1txid'] = result[0]['txid']
	data32['BLockchainLocalRule-1publisherid'] = result[0]['publishers']
	data32['BLockchainLocalPolicies-1txid'] = result1[0]['txid']
	data32['BLockchainLocalPolicies-1publisherid'] = result1[0]['publishers']
	data32['Contract'] = data1[0]['Contract']
	print(data32['BLockchainLocalRule-1txid'] )
	print(data32['BLockchainLocalRule-1publisherid'])
#	data32.update(data2[-1])
#	data32.update(data1[-1])
	print(data2[-1])

	with open("/home/ubuntu/Desktop/Shahbaz_Final_Project/Application/Application.txt", 'w') as f:
	    json.dump(data32, f,indent=4)    


	#print(result[0]['txid'])
	 # 10 most recent items

####################################################################################################################################
	#######################################Store rule in Multichain Service-2(Local Contract Deployment Application)################
	rpcuser = "multichainrpc"
	rpcpassword = "2PZRJWQgycsQU6W6wKFJtPMjXcaXbdMqAu4QjmaDh6ZT"
	rpchost = "127.0.0.1"
	rpcport = "4780"
	chainname = "shahbaz"

	mc1=multichain.MultiChainClient(rpchost, rpcport, rpcuser, rpcpassword)

	#print(mc.getinfo())
	txid1 = mc1.create('stream', 'Localrule', True) # open to all to write
	Agreement = mc1.create('stream', 'LocalServiceAgreement', True) # open to all to write

	#result = mc.getstreaminfo('Localrule')
	#result = mc.liststreams() # all streams


	#result = mc.liststreams('LocalRule') # one specific stream
	txid1 = mc1.publish('LocalRule', 'key1', {'json' : {
	        "Serviceid":"Service2",
	        "Contract": "Local",
	        "LocalRuleHash":hash1,
	        "Servicerthreshould":0.1,
	        "PreviousTrust":0,
	        "ServiceTrust": 0.0,
	        "Service Value":0.0,
	        "Time":current_time         
	           }}) # JSON data
	mc1.subscribe('LocalRule') 
	txid12 = mc1.publish('LocalServiceAgreement', 'key1', {'json' : {
	        "TransactionalHash":txid1        
	           }}) # JSON data
	mc1.subscribe('LocalServiceAgreement') 


	# one asset or stream
	#result = mc.liststreamitems('LocalRule')
	#result = mc.liststreamkeys('LocalRule') # all keys in stream
	#result = mc.liststreamkeys('LocalRule', 'key1')
	#result = mc.getstreamkeysummary('LocalRule', 'key1', 'jsonobjectmerge')
	result2 = mc.liststreamkeyitems('LocalRule', 'key1',False,1)

	#print(result)


	#######################################Store policies in Multichain################

	txid2 = mc.create('stream', 'LocalPolicies', True) # open to all to write

	#result = mc.getstreaminfo('Localrule')
	#result = mc.liststreams() # all streams


	#result = mc.liststreams('LocalRule') # one specific stream
	txid2 = mc.publish('LocalPolicies', 'key1', {'json' : {
	        "Serviceid":"Service2",  
	        "LocalpolicyHash":hash2,
	        "Subject":"Application",
	        "object":"School",
	        "CollaborativeServiceTrust":0.1,
	        "CollaborativeServicePTrust":0.0,
	        "CollaborativeServiceCTrust":0.0,
	        	        "Time":current_time                  
	    }}) # JSON data
	mc.subscribe('LocalPolicies') # one asset or stream
	#result = mc.liststreamitems('LocalRule')
	#result = mc.liststreamkeys('LocalRule') # all keys in stream
	#result = mc.liststreamkeys('LocalRule', 'key1')

	###################################SAmple Code inorder to Search the ItemFrom the Blockchain#######
	import json
	result3 = mc.liststreamkeyitems('LocalPolicies', 'key1',False,1)

	#print(result)


	#my_dict = {}  # create an empty dictionary

	# add key-value pairs to the dictionary

	#my_dict['txid'] = result[0]['txid']
	#my_dict['publisherid'] = result[0]['publishers']
	#print(my_dict)  # {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}

	########################Adaptive Security Engine Recieve Security Tokens for Rule and Policy -2##############################
	
	with open("/home/ubuntu/Desktop/Shahbaz_Final_Project/Application/Application2.txt", "r") as f:
	    print("Security Contract For Service2")
	    data = f.read()    
	    data32 =json.loads(data)
	    ###Key Noticed result[0] only extract the Blockchain variable such as txid ,confirmation,publisherid not Application data
	data32['BLockchainLocalRule-2txid'] = result2[0]['txid']
	data32['BLockchainLocalRule-2publisherid'] = result2[0]['publishers']
	data32['BLockchainLocalPolicies-2txid'] = result3[0]['txid']
	data32['BLockchainLocalPolicies-2publisherid'] = result3[0]['publishers']
	data32['Contract'] = data1[0]['Contract']
#	data32.update(data2[-1])
#	data32.update(data1[-1])

	with open("/home/ubuntu/Desktop/Shahbaz_Final_Project/Application/Application2.txt", 'w') as f:
	    json.dump(data32, f,indent=4)    


	#print(result[0]['txid'])
	 # 10 most recent items
##################################################################################### 

```
# 4.Context engine
1. **The Context engine is embeded in abstractmote.java code**
1. **This Contract increase the trust vlaue of the smart interoperble service in security verifcation**
```java
public final void rxData(DataPacket packet) {
    
          

    
        if (isAcceptedIdPacket(packet)) {
        
        try {
          String uniqueid = UUID.randomUUID().toString();  
          MultiChainUtils.writeRegistrationToStream("Registration",Integer.toString(this.getID()),uniqueid);
                 Thread.sleep(1000);
                       System.out.println("Delay Created By Me ");
                       
                       
                       
                       String key = MultiChainUtils.getCertificateFromStream(
    	    		
	    	        		"268e333bbccd116d5517c813a5fb132c3ee3abc0048f24d291f5ff1cd6b4648f",
	    	    			"H0hRv4/GdUJmpAnIQ5Mt167xsZAoTGyWrorhzJ80LJKvCZ1PyAHZp7vsPQw9XxjFxjK4PkLZ2oX9phRYaDRp5JM=");
	    	    			//System.out.println(Key);
 
                 }
                      catch (InterruptedException ex) {
  // Stop immediately and go home
}
        
        	Json json = null;
        	int src = packet.getSrc().intValue();
        
     //Network Registration Conform Fiorst 
     //Devic Registratiion Confirmed 
     //Service Registration
     
     try {	
     
     
     		                    Date date = new Date();
		                    
                     long StarttimeMilli = date.getTime();
                    System.out.println("Start Time for execution: " + StarttimeMilli);

             
       

	                                File file = new File("/home/ubuntu/Desktop/Shahbaz_Final_Project/Ada-Framework-Shahbaz1/01-GetStarted/Keys/hash"+1+".txt");
       final MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
String shaChecksum = getFileChecksum(shaDigest,file);
byte [] bytes12 = shaChecksum.getBytes(StandardCharsets.UTF_8);
//System.out.println(shaChecksum);

if(DigestCheck(bytes12,1)){
                    System.out.println("Node"+this.getID()+"Verifed");
                    String uniqueid = UUID.randomUUID().toString();
	
	
                   Service1();
                   Service2();
                   Service3();           
          Logs3(StarttimeMilli);           
                    }
                    else{
                    System.out.println("Node"+this.getID()+"Not Verifed");

}
                    
         		}
	catch(IOException e){
               }
               catch(NoSuchAlgorithmException e)
        {
        System.out.println("Exception for NoSuchAlgorithmException in KeyGenInitialize function");
        }
         	    			 			
            SDN_WISE_Callback(packet);
        } else if (isAcceptedIdAddress(packet.getNxhop())) {
            runFlowMatch(packet);
        }
    }
    

```
# 🌾 Smart City Trust Framework 2025 - Complete Implementation
### Context-Aware Trust & Adaptive Security Governance for Smart Agriculture  

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![MultiChain](https://img.shields.io/badge/MultiChain-2.3.3-orange)](https://www.multichain.com/)
[![Contiki-NG](https://img.shields.io/badge/Contiki--NG-Latest-green)](https://github.com/contiki-ng/contiki-ng)

## 📋 Complete Table of Contents

- [System Overview](#-system-overview)
- [Architecture](#-system-architecture)
- [Prerequisites](#-prerequisites)
- [Complete Installation](#-complete-installation-guide)
- [Blockchain Setup](#-multichain-blockchain-setup)
- [Stream Configuration](#-blockchain-streams-configuration)
- [Core Modules](#-core-modules-detailed)
- [Trust Model](#-trust--risk-model-mathematics)
- [Running the System](#-running-the-system)
- [API Documentation](#-api-documentation)
- [Performance Benchmarks](#-performance-benchmarks)
- [Troubleshooting](#-troubleshooting)
- [Monitoring](#-system-monitoring)
- [Citation](#-citation)

---

## 🎯 System Overview

This implementation provides a **complete adaptive security framework** for smart agriculture using:
- **Real-time environmental monitoring** (OpenWeatherMap + SoilGrids APIs)
- **Multi-dimensional trust computation** (Historical + Reputation + Contextual)
- **Dynamic ECC cryptographic tier escalation** (128 → 192 → 256-bit)
- **MultiChain blockchain** for immutable trust records and service registry
- **Smart contract enforcement** of security policies

**Key Innovation**: Automatically escalates cryptographic security when environmental risks increase (e.g., heavy rain >30mm triggers ECC-256 encryption).

---

## 🏗️ System Architecture

```ascii
+---------------------+     +-----------------------+     +-----------------------+
|    Data Layer       |     |   Trust Engine        |     |  Blockchain Layer     |
|                     |     |                       |     |                       |
|  ┌──────────────┐   |     |  ┌─────────────────┐  |     |  ┌─────────────────┐  |
|  │ OpenWeather  │━━━┿━━━━━┿━▶│ Historical     │  |     |  │ Service Registry│  |
|  │   API        │   |     |  │ Trust Engine   │━━┿━━━━━┿━▶│ Stream          │  |
|  └──────────────┘   |     |  └─────────────────┘  |     |  └─────────────────┘  |
|                     |     |                       |     |                       |
|  ┌──────────────┐   |     |  ┌─────────────────┐  |     |  ┌─────────────────┐  |
|  │ SoilGrids    │━━━┿━━━━━┿━▶│ Reputation     │  |     |  │ Trust Records   │  |
|  │   API        │   |     |  │ Trust Engine   │━━┿━━━━━┿━▶│ Stream          │  |
|  └──────────────┘   |     |  └─────────────────┘  |     |  └─────────────────┘  |
|                     |     |                       |     |                       |
|  ┌──────────────┐   |     |  ┌─────────────────┐  |     |  ┌─────────────────┐  |
|  │ IoT Sensors  │━━━┿━━━━━┿━▶│ Contextual     │  |     |  │ Policy Logs     │  |
|  │ (Contiki-NG) │   |     |  │ Trust Engine   │━━┿━━━━━┿━▶│ Stream          │  |
|  └──────────────┘   |     |  └─────────────────┘  |     |  └─────────────────┘  |
+---------------------+     +-----------------------+     +-----------------------+
                                |                                       |
                                v                                       v
+---------------------+     +-----------------------+     +-----------------------+
|  Security Engine    |     |  Crypto Engine        |     |  Policy Engine        |
|                     |     |                       |     |                       |
|  ┌─────────────────┐|     |  ┌─────────────────┐  |     |  ┌─────────────────┐  |
|  │ Risk Assessment │┿━━━━━┿━▶│ ECC Tier       │━━┿━━━━━┿━▶│ Access Control   │  |
|  │   Module        │|     |  │ Selection       │  |     |  │   Engine        │  |
|  └─────────────────┘|     |  │ (128/192/256)   │  |     |  └─────────────────┘  |
|                     |     |  └─────────────────┘  |     |                       |
|  ┌─────────────────┐|     |                       |     |  ┌─────────────────┐  |
|  │ Threat Detection│┿━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━┿━▶│ Session         │  |
|  │   Module        │|     |                       |     |  │ Management      │  |
|  └─────────────────┘|     +-----------------------+     |  └─────────────────┘  |
+---------------------+                                   +-----------------------+
```

---

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04/22.04 LTS (recommended) or Windows 10/11 with WSL2
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB free space
- **Network**: Internet connection for API calls

### Software Requirements
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git wget curl build-essential libssl-dev

# Windows (WSL2)
wsl --install -d Ubuntu-22.04
```

---

## 🔧 Complete Installation Guide

### Step 1: Clone Repository
```bash
git clone https://github.com/Shahbazdefender/smartcity-trust-framework-2025.git
cd smartcity-trust-framework-2025

# Create virtual environment
python3 -m venv trust_env
source trust_env/bin/activate  # Linux/Mac
# trust_env\Scripts\activate  # Windows

# Install Python dependencies
pip install --upgrade pip
pip install requests numpy pandas matplotlib cryptography
```

### Step 2: API Keys Setup
```bash
# Get free API keys
# 1. OpenWeatherMap: https://openweathermap.org/api
# 2. SoilGrids: No API key required

# Set environment variables
echo 'export OPENWEATHER_API_KEY="your_actual_api_key_here"' >> ~/.bashrc
source ~/.bashrc
```

### Step 3: Directory Structure Setup
```bash
# Create necessary directories
mkdir -p logs keys blockchain streams

# Verify structure
tree -a
# Expected output:
# .
# ├── 18november.py
# ├── multichain.py
# ├── updated_Registration.py
# ├── logs/
# ├── keys/
# ├── blockchain/
# └── streams/
```

---

## ⛓️ MultiChain Blockchain Setup

### Step 1: Install MultiChain
```bash
# Download and install MultiChain
cd /tmp
wget https://www.multichain.com/download/multichain-2.3.3.tar.gz
tar -xvzf multichain-2.3.3.tar.gz
cd multichain-2.3.3
sudo mv multichaind multichain-cli /usr/local/bin/

# Verify installation
multichaind --version
# Output: MultiChain 2.3.3 Daemon (community edition)
```

### Step 2: Create Blockchain Networks
We'll create 4 separate blockchains for different services:

```bash
# Create blockchain directories
mkdir -p ~/blockchains/{weather,transport,sf,bank}

# Create and configure each blockchain
for chain in weather transport sf bank; do
    echo "Creating $chain blockchain..."
    multichain-util create $chain
    sed -i 's/default-network-port = [0-9]*/default-network-port = 97'${chain:0:1}'4/' ~/.multichain/$chain/params.dat
    sed -i 's/default-rpc-port = [0-9]*/default-rpc-port = 97'${chain:1:1}'4/' ~/.multichain/$chain/params.dat
done

# Update specific ports
sed -i 's/default-rpc-port = 9744/default-rpc-port = 9724/' ~/.multichain/weather/params.dat
sed -i 's/default-rpc-port = 9744/default-rpc-port = 7202/' ~/.multichain/transport/params.dat
sed -i 's/default-rpc-port = 9744/default-rpc-port = 9582/' ~/.multichain/sf/params.dat
sed -i 's/default-rpc-port = 9744/default-rpc-port = 6458/' ~/.multichain/bank/params.dat
```

### Step 3: Start Blockchain Daemons
```bash
# Start all blockchain daemons
multichaind weather -daemon
multichaind transport -daemon  
multichaind sf -daemon
multichaind bank -daemon

# Check if all are running
multichain-cli weather getinfo
multichain-cli transport getinfo
multichain-cli sf getinfo
multichain-cli bank getinfo
```

### Step 4: Configure RPC Access
```bash
# Generate RPC passwords for each chain
for chain in weather transport sf bank; do
    echo "rpcuser=multichainrpc" > ~/.multichain/$chain/multichain.conf
    echo "rpcpassword=$(openssl rand -base64 32)" >> ~/.multichain/$chain/multichain.conf
    echo "rpcallowip=127.0.0.1" >> ~/.multichain/$chain/multichain.conf
done

# Restart daemons with new configuration
pkill multichaind
sleep 5

multichaind weather -daemon
multichaind transport -daemon
multichaind sf -daemon  
multichaind bank -daemon
```

---

## 📊 Blockchain Streams Configuration

### Step 1: Create Required Streams
Create a Python script to initialize all streams:

```python
# create_streams.py
import multichain
import json

# Blockchain configurations
chains = {
    "weather": {"port": 9724, "password": "2xYe2PpKbiCpuXfHVhJPDUiVuus3k1dinKfMriSCD6dx"},
    "transport": {"port": 7202, "password": "GLKF9X2pi7pLqMcTYE24yGvniKMc9XSHebHPjnbmn5cL"},
    "sf": {"port": 9582, "password": "4WeL79Sh5uwpiT9kGkP4848jNa5jUPoQn31sM3HyYbDv"},
    "bank": {"port": 6458, "password": "45ujj1UkhFS6iVE6ifeo8beW68n9vpk7f48GN4Zb71pb"}
}

# Stream definitions
streams = [
    "Service Registration",
    "TrustStream", 
    "LocalRule",
    "LocalPolicies",
    "LocalServiceAgreement",
    "AuditLog",
    "RiskLog",
    "PerformanceMetrics"
]

for chain_name, config in chains.items():
    print(f"Configuring {chain_name} blockchain...")
    
    try:
        mc = multichain.MultiChainClient("127.0.0.1", config["port"], "multichainrpc", config["password"])
        
        # Create streams
        for stream in streams:
            try:
                result = mc.create('stream', stream, True)
                print(f"  Created stream: {stream}")
            except Exception as e:
                print(f"  Stream {stream} may already exist: {e}")
                
    except Exception as e:
        print(f"Error connecting to {chain_name}: {e}")

print("Stream creation completed!")
```

Run the stream creation script:
```bash
python create_streams.py
```

### Step 2: Verify Stream Creation
```bash
# Check streams on each blockchain
for chain in weather transport sf bank; do
    echo "=== $chain Blockchain Streams ==="
    multichain-cli $chain liststreams
    echo
done
```

---

## 🔧 Core Modules Detailed

### 1. Main Trust Framework (`18november.py`)
**Complete adaptive security implementation**

#### Key Components:
```python
# Trust Computation Functions
compute_historical_trust()    # Time-decayed historical performance
compute_reputation_trust()    # Peer feedback weighted by credibility  
compute_contextual_trust()    # Environmental context modifiers
compute_risk()               # Environmental + service risk assessment
compute_overall_trust()      # Weighted combination of all trust components
```

#### Configuration:
```python
# Crop-specific environmental thresholds
CROP_THRESHOLDS = {
    "wheat": {"temp": (15, 35), "humidity": (40, 80), "soil_moisture": (20, 60)},
    "maize": {"temp": (18, 38), "humidity": (50, 85), "soil_moisture": (25, 70)},
    "rice":  {"temp": (20, 40), "humidity": (60, 90), "soil_moisture": (40, 80)},
}

# Context weights for trust computation
CONTEXT_WEIGHTS = {
    "sensor_integrity": 0.25,
    "location_validity": 0.2,
    "environment_alignment": 0.35, 
    "time_freshness": 0.2
}
```

### 2. MultiChain Client (`multichain.py`)
**Robust blockchain interaction library**

#### Key Features:
- SSL/TLS support for secure communication
- Comprehensive error handling
- Stream operations (publish, subscribe, query)
- JSON-RPC protocol implementation

#### Usage Example:
```python
from multichain import MultiChainClient

# Initialize client
mc = MultiChainClient("127.0.0.1", 9724, "multichainrpc", "your_password")

# Publish trust data
txid = mc.publish('TrustStream', 'trust', {'json': trust_data})

# Query data
items = mc.liststreamitems('TrustStream', 10)  # Last 10 items
```

### 3. Service Registration (`updated_Registration.py`)
**Service registry and authentication system**

#### Service Definitions:
```python
services = {
    "CA": {
        "Service name": "CA",
        "Authentication": "123",
        "Authorization": ["weather", "transport", "sf", "bank"],
        "Access Control": ["0"]  # Highest privilege
    },
    "weather": {
        "Service name": "weather", 
        "Authentication": "321",
        "Authorization": ["CA", "transport", "sf", "bank"],
        "Access Control": ["1"]
    }
    # ... more services
}
```

---

## 📐 Trust & Risk Model Mathematics

### 1. Historical Trust (Definition 1)
$$T_{\text{Hist}}(t) = \frac{\sum \delta^{(t - t_j)/\Delta t} \cdot s_{t_j}}{\sum \delta^{(t - t_j)/\Delta t}}$$

**Where:**
- $\delta = 0.9$ (decay factor)
- $\Delta t = 24$ hours (time window)
- $s_{t_j}$ = trust score at time $t_j$

### 2. Reputation Trust (Definition 2) 
$$T_{\text{Rept}}(t) = \frac{\sum c_j \cdot f_j}{\sum c_j}$$

**Where:**
- $c_j$ = credibility of peer $j$
- $f_j$ = feedback from peer $j$

### 3. Contextual Trust (Definition 3)
$$T_{\text{Ctx}}(t) = \min\!\left(0.7 \times (M_{\text{rain}}^{0.6} \times M_{\text{temp}}^{0.4}), 1\right)$$

**Environmental Modifiers:**
- $M_{\text{rain}} = 1 - \frac{\text{rainfall}}{50}$ (if rain < 50mm else 0)
- $M_{\text{temp}} = 1 - \frac{|T-28|}{10}$ (if |T-28| < 10 else 0)

### 4. Overall Trust & Risk
$$T_{\text{Overall}} = w_1 T_{\text{Hist}} + w_2 T_{\text{Rept}} + w_3 T_{\text{Ctx}}$$
$$R = \frac{R_{\text{Env}} + R_{\text{Service}}}{2}$$

**Dynamic Weights:**
- $w_1 = 0.5 - 0.2R$ (Historical weight decreases with risk)
- $w_2 = 0.3 + 0.1R$ (Reputation weight increases with risk)  
- $w_3 = 1 - w_1 - w_2$ (Contextual weight adapts)

---

## 🚀 Running the System

### Step 1: Service Registration
```bash
# Register all services on blockchain
python updated_Registration.py

# Expected Output:
# Authentication values from last 5 services:
# Service 1 - Name: CA, Authentication: 123
# Service 2 - Name: weather, Authentication: 321
# Service 3 - Name: transport, Authentication: 678
# Service 4 - Name: sf, Authentication: 456  
# Service 5 - Name: bnk, Authentication: 789
```

### Step 2: Real-time Trust Assessment
```bash
# Run continuous trust monitoring
python 18november.py

# Expected Output:
# [2025] R=0.234 → T_overall=0.812 → ECC-128 → ALLOW
# [2025] R=0.521 → T_overall=0.689 → ECC-192 → ALLOW  
# [2025] R=0.782 → T_overall=0.423 → ECC-256 → DENY
# [2025] R=0.845 → Session TERMINATED → ECC-256 → DENY
```

### Step 3: Performance Benchmarking
```bash
# Run comprehensive performance tests
python 18november.py --benchmark

# This generates:
# - 11 performance figures (PNG format)
# - CSV datasets for analysis
# - Blockchain performance metrics
```

### Step 4: Continuous Monitoring
```bash
# Create monitoring script
cat > monitor_system.sh << 'EOF'
#!/bin/bash
while true; do
    echo "=== System Status $(date) ==="
    python 18november.py
    sleep 300  # Run every 5 minutes
done
EOF

chmod +x monitor_system.sh
./monitor_system.sh
```

---

## 📊 Performance Benchmarks

### Generated Analysis Files:

| File | Description | Metrics |
|------|-------------|---------|
| **Exp1(a).png** | Fixed ECC tiers throughput | Requests/sec vs Number of requests |
| **Exp1(b).png** | Fixed ECC tiers delay | Delay (ms) vs Number of requests |
| **Exp2(a).png** | Escalation paths throughput | Throughput for 128→192, 128→256, 192→256 |
| **Exp2(b).png** | Escalation paths delay | End-to-end delay for escalation paths |
| **Collab_NoEsc_*.png** | Collaborative execution without escalation | Execution time, throughput, delay |
| **Collab_Esc_*.png** | Collaborative execution with escalation | Performance with tier changes |
| **ECC_Escalation_Timeline.png** | Real-time tier escalation | Risk vs ECC tier over time |

### Expected Performance:

| Scenario | ECC Tier | Throughput | Avg Delay | Use Case |
|----------|----------|------------|-----------|----------|
| Normal conditions | ECC-128 | 18.40 req/s | 1.72 ms | Low risk |
| Moderate risk | ECC-192 | 15.25 req/s | 1.47 ms | Medium risk |
| High risk | ECC-256 | 12.90 req/s | 1.32 ms | Heavy rain, anomalies |
| Escalation 128→256 | Mixed | 10.00 req/s | 2.68 ms | Risk detection |

---

## 🔌 API Documentation

### Trust Framework Methods

#### `compute_historical_trust(service_id, current_time)`
```python
def compute_historical_trust(service_id, now):
    """
    Calculate historical trust using exponential decay.
    
    Args:
        service_id (str): Unique identifier for the service
        now (float): Current timestamp for decay calculation
        
    Returns:
        float: Historical trust score between 0.0 and 1.0
    """
```

#### `select_ecc_tier(risk_score, overall_trust)`
```python
def select_ecc_tier(R, T_overall):
    """
    Dynamically select ECC cryptographic tier based on risk and trust.
    
    Args:
        R (float): Current risk score (0.0 to 1.0)
        T_overall (float): Overall trust score (0.0 to 1.0)
        
    Returns:
        int: ECC tier (128, 192, or 256)
        
    Policy:
        - T_overall < 0.7 OR R > 0.5 → ECC-256
        - R > 0.7 → ECC-256 (high risk)
        - R < 0.3 → ECC-128 (low risk)  
        - Otherwise → ECC-192 (medium risk)
    """
```

### MultiChain Methods

#### `publish(stream_name, key, data)`
```python
def publish(stream, key, data):
    """
    Publish data to blockchain stream.
    
    Args:
        stream (str): Target stream name
        key (str): Key for data retrieval
        data (dict): JSON-serializable data
        
    Returns:
        str: Transaction ID if successful
        
    Raises:
        Exception: If publishing fails
    """
```

#### `liststreamitems(stream_name, count=10, verbose=False)`
```python
def liststreamitems(stream, count=10, verbose=False):
    """
    Retrieve items from blockchain stream.
    
    Args:
        stream (str): Stream name to query
        count (int): Number of items to retrieve
        verbose (bool): Include blockchain metadata
        
    Returns:
        list: Stream items with data and metadata
    """
```

---

## 🐛 Troubleshooting

### Common Issues & Solutions

#### 1. MultiChain Connection Issues
```bash
# Check if daemons are running
ps aux | grep multichaind

# Check RPC configuration
cat ~/.multichain/weather/multichain.conf

# Restart daemons if needed
pkill multichaind
sleep 3
multichaind weather -daemon
multichaind transport -daemon
multichaind sf -daemon
multichaind bank -daemon
```

#### 2. API Key Problems
```python
# Test OpenWeatherMap API
import requests
API_KEY = "your_api_key"
response = requests.get(f"http://api.openweathermap.org/data/2.5/weather?q=Islamabad&appid={API_KEY}")
print(response.status_code)  # Should be 200

# Test SoilGrids API  
response = requests.post("https://rest.isric.org/soilgrids/v2.0/properties/query", 
                        json={"lon": 73.0479, "lat": 33.6844, "property": ["wg3"]})
print(response.status_code)  # Should be 200
```

#### 3. Python Package Issues
```bash
# Recreate virtual environment
deactivate
rm -rf trust_env
python3 -m venv trust_env
source trust_env/bin/activate
pip install -r requirements.txt

# Or install individually
pip install requests numpy pandas matplotlib cryptography
```

#### 4. Permission Problems
```bash
# Fix file permissions
sudo chmod -R 755 ~/.multichain/
sudo chown -R $USER:$USER ~/.multichain/

# Check blockchain file permissions
ls -la ~/.multichain/weather/
```

### Debug Mode
```python
# Enable debug output
import logging
logging.basicConfig(level=logging.DEBUG)

# Test individual components
from 18november import compute_historical_trust, compute_risk
test_trust = compute_historical_trust("test_service", time.time())
print(f"Test trust: {test_trust}")
```

---

## 📈 System Monitoring

### Health Check Script
```python
# health_check.py
import multichain
import requests
import json
from datetime import datetime

def system_health_check():
    print(f"=== System Health Check {datetime.now()} ===")
    
    # Check blockchain connections
    chains = {
        "weather": 9724,
        "transport": 7202, 
        "sf": 9582,
        "bank": 6458
    }
    
    for chain, port in chains.items():
        try:
            mc = multichain.MultiChainClient("127.0.0.1", port, "multichainrpc", "password")
            info = mc.getinfo()
            print(f"✓ {chain} blockchain: OK (blocks: {info['blocks']})")
        except:
            print(f"✗ {chain} blockchain: OFFLINE")
    
    # Check APIs
    try:
        response = requests.get("http://api.openweathermap.org/data/2.5/weather?q=London&appid=demo", timeout=10)
        print(f"✓ OpenWeatherMap API: OK (status: {response.status_code})")
    except:
        print("✗ OpenWeatherMap API: OFFLINE")
        
    try:
        response = requests.post("https://rest.isric.org/soilgrids/v2.0/properties/query", timeout=10)
        print(f"✓ SoilGrids API: OK (status: {response.status_code})")
    except:
        print("✗ SoilGrids API: OFFLINE")

if __name__ == "__main__":
    system_health_check()
```

### Performance Monitoring
```bash
# Monitor system resources
watch -n 5 'echo "=== Blockchain Resources ===" && \
ps aux | grep multichaind | grep -v grep && \
echo "=== Memory Usage ===" && \
free -h && echo "=== Disk Usage ===" && df -h'
```

---


## 🆘 Support

### Getting Help
1. **Check logs**: `tail -f logs/trust_log.json`
2. **Verify blockchain**: `multichain-cli weather getinfo`
3. **Test APIs**: Run `health_check.py`
4. **Check issues**: [GitHub Issues Page]



