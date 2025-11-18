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
# Smart Agriculture — Context-Aware Trust & Adaptive Security Governance

Repository: https://github.com/Shahbazdefender/A-Smart-Contract-Based-Adaptive-Security-Governance-Architecture-for-Smart-City-Service

Paper: "Context-Aware Trust Governance for Adaptive Security in Collaborative Smart City Services" — PeerJ Computer Science, 2025

Section: Smart Agriculture Use Case  
Authors: Usama Antuley, Muhammad Afnan, Shahbaz Siddiqui, Sufian Hameed, Dirk Draheim, Syed Attique Shah  
Date: November 16, 2025 — Karachi, Pakistan

---

## Overview

This repository implements the Smart Agriculture use case:
- IoT sensors (soil moisture, temperature, pH) simulated via Cooja/Contiki hooks.
- Integration points for OpenWeather and SoilGrids (mocked).
- Trust & risk engine (trust_engine.py) implementing the mathematical model.
- Key-management: bulk ECC key generation script.
- Policy enforcement via mocked MultiChain publish to streams (LocalRule, LocalPolicies, AuditLog).
- ECC tier escalation and policy decisions (delay fertilizer when rain risk is high).

---

## Quickstart

1. Clone the repo.
2. Generate keys:
   ```bash
   bash scripts/generate_keys.sh       # default: generates 61 keys per ECC curve
