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
# 🌾 Context-Aware Trust & Adaptive Security Governance for Smart Agriculture
### A Smart Contract-Based Adaptive Security Architecture for Collaborative Smart City Services  
**Smart Agriculture Use Case**
This repository contains the code, scripts, figures and supporting artifacts used to reproduce the experiments and results reported in the PeerJ paper. The code implements a context-aware trust & risk engine, multichain integration hooks (logging/publishing), and an ECC tier escalation module used in the Smart Agriculture use-case. The README below tells readers how to run the code, what to expect, and highlights the main formulas and small code examples used in the experiments.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Contiki-NG](https://img.shields.io/badge/Contiki--NG-Latest-green)](https://github.com/contiki-ng/contiki-ng)
[![MultiChain](https://img.shields.io/badge/MultiChain-Blockchain-orange)](https://www.multichain.com/)

> **Real-time risk-aware ECC tier escalation (128 → 192 → 256-bit)**  
> **Location**: Karachi, Pakistan | **Date**: November 2025

---

### 📄 Citation
Usama Antuley, Muhammad Afnan, Shahbaz Siddiqui, Sufian Hameed, Dirk Draheim, Syed Attique Shah. "Context-Aware Trust Governance for Adaptive Security in Collaborative Smart City Services." PeerJ Computer Science, 2025 (In Press).

text
---

### 🎯 Use Case Overview
This repository implements a **context-aware, trust-based adaptive security governance system** for **smart agriculture**, preventing unsafe actions (e.g., fertilizing during heavy rain) using:
- Real-time weather (OpenWeatherMap API)
- Soil properties (SoilGrids ISRIC API)
- Dynamic trust computation (Historical + Reputation + Contextual)
- Risk-aware ECC encryption tier escalation
- MultiChain blockchain for immutable policy enforcement and audit logs

**Goal**: High security when needed, low latency when safe.

---

### 🏗️ System Architecture

```ascii
+--------------------+     +---------------------+
|   IoT Sensors      |<--->| SD-IoT Controller   |
| (Contiki-NG/Cooja) |     | (AbstractMote.java) |
+--------------------+     +---------------------+
            |                       |
            v                       v
+--------------------+   +---------------------+
|  Context Engine    |   | Trust & Risk Engine |
| (OpenWeather +     |   | (trust_engine.py)   |
|  SoilGrids API)    |   +---------------------+
+--------------------+
            |           
            v           
+--------------------------------------------------+
|           MultiChain Blockchain                  |
|  Streams: LocalRule, LocalPolicies, AuditLog     |
+--------------------------------------------------+
            |
            v
+--------------------+
| ECC Tier Escalation|
| 128 → 192 → 256    |
+--------------------+

# 🌾 Context-Aware Trust & Adaptive Security Governance for Smart Agriculture

### A Smart Contract-Based Adaptive Security Architecture for Collaborative Smart City Services

This repository provides the **complete programmable script**, **trust engine**, **policy engine**, **key management module**, **context engine**, and **ECC tier escalation benchmarks** used in the PeerJ Computer Science 2025 paper:

> **Context-Aware Trust Governance for Adaptive Security in Collaborative Smart City Services**

It also includes the Python script **`smartcity_trust_framework_2025.py`**, which reproduces all trust, risk, ECC performance, and collaborative execution experiments presented in the paper.

---

# 📁 Repository Structure

```
.
├── paper/
│   └── PeerJ_Journal_Paper Submission.pdf
├── code/
│   ├── smartcity_trust_framework_2025.py   # Main trust engine + ECC benchmark
│   ├── generate_keys.sh                    # Key Management Module
│   ├── deploy_contracts.py                 # Blockchain Rule/Policy engine
│   ├── logs/                               # Generated CSVs + experiment figures
│   └── README.md
```

---

# 1️⃣ Key Management Module (ECC-128 / ECC-192 / ECC-256)

### ✔ Generates 50+ ECC keypairs on each service node

### ✔ Supports 3 cryptographic strength levels

### ✔ Used by interoperable services, SDN controller, client nodes

## 📌 Features

1. Generates **public/private keypairs + SHA256 hash** for identity validation.
2. Creates separate ECC directories:

   * `ECC-128/`
   * `ECC-192/`
   * `ECC-256/`
3. Uses OpenSSL curves:

   * `prime128v1`
   * `prime192v1`
   * `prime256v1`
4. Output appended to security.json

---

## 🔐 Key Generation Bash Script (Full Version)

```bash
#!/bin/bash

# Generate 61 ECC key pairs
for i in {1..61}
do
    echo "Generating ECC keypair $i..."

    # ECC-128
    openssl ecparam -name prime128v1 -genkey -noout -out private-key$i.pem
    openssl ec -in private-key$i.pem -pubout -out public-key$i.pem

    # Hash the private key
    openssl dgst -sha256 -binary private-key$i.pem > hash$i.txt

done

echo "Keys Successfully Generated."
echo "}" >> security.json
```

---

# 2️⃣ Service Management Module

### ✔ Updates `ServiceSecurity.json` with local trust, previous trust, threshold

### ✔ Java AbstractMote calls this JSON to update behavioral trust

### ✔ Python integrates with Java using file-based filling

## 📌 Python Script Used to Manage & Append Service Security Rules

```python
import json, os, hashlib
from datetime import datetime

data1 = []
data2 = []

def encode_json(data):
    return json.dumps(data, indent=4)

def decode_json(json_data):
    return json.loads(json_data)

# Load previous contract state
if os.path.exists("ServiceSecurity.json"):
    with open("ServiceSecurity.json", "r") as f:
        data1 = decode_json(f.read())

# Service Management Logic

def ServiceManagement():
    while True:
        commit = input("Enter commit to add rule: ")
        if commit != "commit":
            break

        now = datetime.now().strftime("%H:%M:%S")

        data1.append({
            "Serviceid": "Service1",
            "Contract": "Local",
            "LocalRuleHash": hash1,
            "Servicerthreshould": 0.0,
            "PreviousTrust": 0.0,
            "ServiceTrust": 0.0,
            "Role": "Admin",
            "Authorization": ["Create", "Add", "Delete", "Display"],
            "Time": now
        })

        data2.append({
            "LocalpolicyHash": hash2,
            "Subject": "Service1",
            "object": "Service2",
            "CollaborativeServiceTrust": 0.0,
            "CollaborativeServicePTrust": 0.0,
            "CollaborativeServiceCTrust": 0.0,
            "Time": now
        })
```

---

# 3️⃣ Rule Engine & Policy Engine (Blockchain Contract Layer)

### ✔ Generates **Local Rules** & **Local Policies** dynamically

### ✔ Stores Contracts on MultiChain Blockchain

### ✔ Ensures tamper-proof & distributed authorization

## 📌 Python Snippet — Blockchain Rule/Policy Storage

```python
from multichain import MultiChainClient
from datetime import datetime
import json

rpcuser = "multichainrpc"
rpcpassword = "xxxxxxxx"
rpchost = "127.0.0.1"
rpcport = "2652"

mc = MultiChainClient(rpchost, rpcport, rpcuser, rpcpassword)

# Create LocalRule stream
mc.create('stream', 'LocalRule', True)

# Publish rule
mc.publish('LocalRule', 'key1', {'json': {
    "Serviceid": "Service1",
    "Contract": "Local",
    "LocalRuleHash": hash1,
    "Servicerthreshould": 0.1,
    "PreviousTrust": 0,
    "ServiceTrust": 0,
    "Time": datetime.now().isoformat()
}})

# Create LocalPolicies stream
mc.create('stream', 'LocalPolicies', True)

# Publish policy
mc.publish('LocalPolicies', 'key1', {'json': {
    "Serviceid": "Service1",
    "LocalpolicyHash": hash2,
    "Subject": "App1",
    "object": "App2",
    "CollaborativeServiceTrust": 0.1,
    "CollaborativeServicePTrust": 0.0,
    "CollaborativeServiceCTrust": 0.0,
    "Time": datetime.now().isoformat()
}})
```

---

# 4️⃣ Context Engine (Integrated in Contiki-NG AbstractMote.java)

### ✔ Real-time trust elevation

### ✔ Uses blockchain certificates + ECC key validation

### ✔ Runs inside **Cooja simulator (Contiki-NG)**

## 📌 Java Snippet — Context Verification Logic

```java
public final void rxData(DataPacket packet) {

    if (isAcceptedIdPacket(packet)) {

        try {
            String uniqueid = UUID.randomUUID().toString();  
            MultiChainUtils.writeRegistrationToStream(
                "Registration", Integer.toString(this.getID()), uniqueid);
            Thread.sleep(1000);

            String key = MultiChainUtils.getCertificateFromStream(
                "txid-here",
                "publisher-key-here"
            );

        } catch (InterruptedException ex) {
            // handle interruption
        }

        try {
            File file = new File("hash1.txt");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            String checksum = getFileChecksum(sha, file);

            if (DigestCheck(checksum.getBytes(), 1)) {
                System.out.println("Node " + this.getID() + " Verified");
                Service1(); Service2(); Service3();
            } else {
                System.out.println("Node " + this.getID() + " Not Verified");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        SDN_WISE_Callback(packet);
    }
}
```

---

# 5️⃣ Smartcity Trust Engine (Python) — Main Script Overview

The script:

* Retrieves **OpenWeather + SoilGrids** context
* Computes **Historical Trust, Reputation Trust, Contextual Trust**
* Aggregates final trust score
* Computes **overall risk**
* Selects ECC tier dynamically
* Optionally writes to blockchain

Run:

```bash
python smartcity_trust_framework_2025.py
```

Run full benchmark:

```bash
python smartcity_trust_framework_2025.py --benchmark
```

---

# 6️⃣ Mathematical Model Used (Complete Paper Formulae)

### 📌 Historical Trust

```
T_Hist = Σ[δ^(t - t_j)/Δt * s_j] / Σ[δ^(t - t_j)/Δt]
```

### 📌 Reputation Trust

```
T_Rept = Σ(c_j * f_j) / Σ(c_j)
```

### 📌 Contextual Trust (Geometric Aggregation)

```
T_Ctx = min( T_base × Π M_k^α_k , 1 )
```

### 📌 Overall Trust

```
T_Overall = w1*T_Hist + w2*T_Rept + w3*T_Ctx
```

### 📌 Risk Score

```
R = (R_Env + R_Service) / 2
R_Service = 1 - T_Hist
```

### 📌 Dynamic Weight Adaptation

```
w1 = 0.5 - 0.2R
w2 = 0.3 + 0.1R
w3 = 1 - w1 - w2
```

---

# 7️⃣ ECC Tier Escalation

```
If T_Overall < 0.7 OR R > 0.5: use ECC-256
If R < 0.3: use ECC-128
Else: use ECC-192
```

---

# 8️⃣ Benchmark Output

When running:

```
python smartcity_trust_framework_2025.py --benchmark
```

It generates:

```
Exp1(a).png
Exp1(b).png
Exp2(a).png
Exp2(b).png
Exp3(a).png
Exp3(b).png
Collab_NoEsc_Exec_Throughput.png
Collab_NoEsc_Delay.png
Collab_Esc_Exec_Throughput.png
Collab_Esc_Delay.png
ECC_Escalation_Timeline.png
```

All figures exactly match those presented in the PeerJ paper.

---

