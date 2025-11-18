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



# 2.Rule Engine and Policy engine Contract

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
The repository includes:

✔ Full trust governance framework
✔ ECC-based adaptive security engine
✔ Blockchain rule & policy engine (MultiChain)
✔ Context engine with real APIs
✔ Smart agriculture use case
✔ All code required by PeerJ reproducing experiments
✔ Benchmark engine that regenerates all figures included in the paper

📁 Repository Structure
.
├── code/
│   ├── smartcity_trust_framework_2025.py      # Main Trust + Risk + ECC Engine
│   ├── generate_keys.sh                       # Key Management Module
│   ├── deploy_contracts.py                    # Blockchain Rule/Policy Engine
│   ├── logs/                                  # Auto-generated logs + PNG figures
│   └── README.md
│
├── paper/
│   └── PeerJ_Journal_Paper Submission.pdf     # Submitted manuscript
│
└── README.md


