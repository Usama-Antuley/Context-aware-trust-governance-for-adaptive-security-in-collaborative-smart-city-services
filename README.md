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

Deploy policies (mock):

python3 trust_engine/deploy_contracts.py


Run a simulation:

python3 trust_engine/simulate_rain.py --rain 35 --temp 38


(Optional) Start Cooja with cooja/agriculture.csc if you have Contiki/Cooja set up.

File map (important files)

scripts/generate_keys.sh — key generation (ECC-128/192/256).

trust_engine/trust_engine.py — main trust & risk engine.

trust_engine/deploy_contracts.py — publish policies to MultiChain (mock).

trust_engine/simulate_rain.py — scenario runner.

cooja/AbstractMote.java — example Cooja mote integration snippet.

blockchain/ServiceSecurity.json — sample service state.

Contact

Shahbaz Siddiqui — shahbazdefender@gmail.com


---

### 2) scripts/generate_keys.sh
```bash
#!/usr/bin/env bash
# scripts/generate_keys.sh
# Generate multiple ECC keypairs and SHA256 hashes per curve.
# Usage: ./scripts/generate_keys.sh [NUM_KEYS]
# Default NUM_KEYS = 61

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BASE_DIR="${REPO_ROOT}/Keys"
NUM_KEYS="${1:-61}"

declare -A CURVES
CURVES["ECC-128"]="prime128v1"
CURVES["ECC-192"]="prime192v1"
CURVES["ECC-256"]="prime256v1"

echo "Generating ${NUM_KEYS} keys per curve under ${BASE_DIR} ..."

for label in "${!CURVES[@]}"; do
  curve="${CURVES[$label]}"
  out="${BASE_DIR}/${label}"
  mkdir -p "${out}"
  echo " - ${label} (${curve}) -> ${out}"
  for i in $(seq 1 "${NUM_KEYS}"); do
    priv="${out}/private-key${i}.pem"
    pub="${out}/public-key${i}.pem"
    hash="${out}/hash${i}.sha256"

    # generate private key
    openssl ecparam -name "${curve}" -genkey -noout -out "${priv}"

    # generate public key
    openssl ec -in "${priv}" -pubout -out "${pub}"

    # sha256 of the private key as a quick integrity/ref
    openssl dgst -sha256 -binary "${priv}" | xxd -p -c 256 > "${hash}"

    # secure perms on private key
    chmod 600 "${priv}"
    # progress dot
    printf '.'
  done
  echo ""
done

echo "Key generation finished. Keys stored in ${BASE_DIR}"

3) trust_engine/trust_engine.py
#!/usr/bin/env python3
# trust_engine/trust_engine.py
"""
Trust & Risk Engine for Smart Agriculture use-case.
Implements the mathematical model from the paper.
"""

import time
from typing import List, Tuple, Dict

# Parameters
DECAY = 0.9
DELTA_T_HOURS = 24.0
T_BASE = 0.7
ALPHA_RAIN = 0.6
ALPHA_TEMP = 0.4

def hours_between(now_ts: float, ts: float) -> float:
    return max(0.0, (now_ts - ts) / 3600.0)

class TrustEngine:
    def _init_(self, now_ts: float = None):
        self.now_ts = now_ts or time.time()

    def historical_trust(self, past_scores: List[Tuple[float, float]]) -> float:
        num = 0.0
        den = 0.0
        for ts, s in past_scores:
            h = hours_between(self.now_ts, ts)
            weight = DECAY ** (h / DELTA_T_HOURS)
            num += weight * s
            den += weight
        return num / den if den > 0 else 0.0

    def reputation_trust(self, feedbacks: List[Tuple[float, float]]) -> float:
        num = 0.0
        den = 0.0
        for c, f in feedbacks:
            num += c * f
            den += c
        return num / den if den > 0 else 0.0

    def contextual_trust(self, temp: float, rain_mm: float) -> float:
        m_rain = max(0.0, 1 - (rain_mm / 50.0)) if rain_mm < 50 else 0.0
        m_temp = max(0.0, 1 - (abs(temp - 28.0) / 10.0)) if abs(temp - 28.0) < 10 else 0.0
        prod = (m_rain * ALPHA_RAIN) * (m_temp * ALPHA_TEMP)
        return min(T_BASE * prod, 1.0)

    def risk_environment(self, temp: float, rain_mm: float) -> float:
        indicators = []
        indicators.append(1 if abs(temp - 28.0) > 5.0 else 0)
        indicators.append(1 if rain_mm > 20.0 else 0)
        return sum(indicators) / len(indicators)

    def risk_service(self, t_hist: float) -> float:
        return 1.0 - t_hist

    def overall_trust(self, t_hist: float, t_rept: float, t_ctx: float, R: float):
        w1 = max(0.0, 0.5 - 0.2 * R)
        w2 = max(0.0, 0.3 + 0.1 * R)
        w3 = max(0.0, 1.0 - w1 - w2)
        T = w1 * t_hist + w2 * t_rept + w3 * t_ctx
        return T, (w1, w2, w3)

def compute_trust_and_risk(
    past_scores: List[Tuple[float, float]],
    feedbacks: List[Tuple[float, float]],
    temp: float,
    rain_mm: float,
    now_ts: float = None
) -> Dict:
    te = TrustEngine(now_ts)
    t_hist = te.historical_trust(past_scores)
    t_rept = te.reputation_trust(feedbacks)
    t_ctx = te.contextual_trust(temp, rain_mm)

    R_env = te.risk_environment(temp, rain_mm)
    R_service = te.risk_service(t_hist)
    R = (R_env + R_service) / 2.0

    T_overall, weights = te.overall_trust(t_hist, t_rept, t_ctx, R)

    # ECC-tier decision and DENY rule
    if T_overall < 0.5:
        ecc_tier = 'DENY'
    elif T_overall < 0.7 or R > 0.5:
        ecc_tier = 'ECC-256'
    else:
        ecc_tier = 'ECC-128'

    return {
        'T_hist': t_hist,
        'T_rept': t_rept,
        'T_ctx': t_ctx,
        'T_overall': T_overall,
        'weights': weights,
        'R_env': R_env,
        'R_service': R_service,
        'R': R,
        'ecc_tier': ecc_tier
    }

if _name_ == '_main_':
    now = time.time()
    past = [(now - 3600 * 24 * i, 0.8 - 0.01 * i) for i in range(1, 6)]
    feedbacks = [(1.0, 0.9), (0.8, 0.7)]
    res = compute_trust_and_risk(past, feedbacks, temp=31.0, rain_mm=5.0, now_ts=now)
    import json
    print(json.dumps(res, indent=2))

4) trust_engine/deploy_contracts.py
#!/usr/bin/env python3
# trust_engine/deploy_contracts.py
"""
Mock deployer for policies (publishes to mocked MultiChain streams).
Replace MultiChainClientMock with actual multichain library / RPC for production.
"""

import time
import json
from pathlib import Path

SERVICE_POLICY = {
    "rule": "if rain > 30: delay_fertilizer = true",
    "ecc_tier": "256 if T_Overall < 0.7 else 128"
}

class MultiChainClientMock:
    def _init_(self):
        self.streams = {}

    def publish(self, stream: str, key: str, value: dict):
        self.streams.setdefault(stream, []).append({
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'key': key,
            'value': value
        })
        print(f"Published to stream '{stream}' key='{key}'")

    def dump(self, path: Path):
        path.write_text(json.dumps(self.streams, indent=2))
        print(f"Mock streams dumped to {path}")

if _name_ == '_main_':
    mc = MultiChainClientMock()
    mc.publish('LocalPolicies', 'agri_policy', {'json': SERVICE_POLICY})
    mc.publish('LocalRule', 'service_threshold', {'json': {
        'Serviceid': 'AgricultureService',
        'Servicerthreshould': 0.7,
        'Time': time.strftime('%Y-%m-%d %H:%M:%S')
    }})
    mc.publish('AuditLog', 'init', {'json': {'note': 'policy deployed'}})

    # dump to file for inspection
    out = Path(_file_).resolve().parent.parent / 'blockchain' / 'mock_streams.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    mc.dump(out)

5) trust_engine/simulate_rain.py
#!/usr/bin/env python3
# trust_engine/simulate_rain.py
"""
Small simulator that uses trust_engine to compute decisions for given rain/temp.
"""

import argparse
import time
import json
from trust_engine import compute_trust_and_risk

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--rain', type=float, default=0.0, help='rain mm')
    p.add_argument('--temp', type=float, default=28.0, help='temperature Celsius')
    args = p.parse_args()

    now = time.time()
    # sample past trust scores (timestamp, score)
    past = [(now - 3600 * 24 * i, 0.8) for i in range(1, 6)]
    feedbacks = [(1.0, 0.8), (0.8, 0.75)]

    res = compute_trust_and_risk(past, feedbacks, temp=args.temp, rain_mm=args.rain, now_ts=now)
    print(json.dumps(res, indent=2))

    # enforcement example
    if args.rain > 30:
        print('POLICY ACTION: delay_fertilizer = true')
    if res['T_overall'] == 'DENY' or res['ecc_tier'] == 'DENY':
        print('POLICY ACTION: deny access (block command)')
    else:
        print(f"Selected ECC Tier: {res['ecc_tier']}")

if _name_ == '_main_':
    main()

6) cooja/AbstractMote.java
// cooja/AbstractMote.java
// Example snippet to show integration points for Cooja (pseudo-code).

public class AbstractMote {
    // placeholder functions that would connect to real APIs or local trust engine
    public static double getTemperature(double lat, double lon) { return 31.0; }
    public static double getRainForecast(double lat, double lon) { return 5.0; }
    public static double getPH(double lat, double lon) { return 7.1; }

    public void rxData(DataPacket packet) {
        double lat = 24.8607, lon = 67.0011;
        double temp = getTemperature(lat, lon);
        double rain = getRainForecast(lat, lon);
        double pH = getPH(lat, lon);

        double R_env = 0.0;
        if (Math.abs(temp - 28.0) > 5.0) R_env += 1.0;
        if (rain > 20.0) R_env += 1.0;
        R_env /= 2.0;

        double T_Overall = TrustEngineWrapper.compute(lat, lon, temp, rain, pH);

        if (T_Overall < 0.5) {
            rejectCommand();
        } else if (T_Overall < 0.7 || R_env > 0.5) {
            useECC256();
        } else {
            useECC128();
        }

        MultiChainUtils.publishTrust(T_Overall, R_env, getECCTier());
    }

    // stub methods
    void rejectCommand() { /* drop / block */ }
    void useECC256() { /* set ECC-256 */ }
    void useECC128() { /* set ECC-128 */ }
    String getECCTier() { return "ECC-128"; }
}

7) blockchain/ServiceSecurity.json
{
  "Serviceid": "AgricultureService",
  "Contract": "Local",
  "Servicerthreshould": 0.7,
  "ServiceTrust": 0.78,
  "PreviousTrust": 0.80,
  "CollaborativeServiceCTrust": 0.65,
  "Time": "2025-11-16 12:00:00"
}

8) .gitignore
# Keys and sensitive data
Keys/
_pycache_/
*.pyc
*.log
.env
.blockchain/
blockchain/mock_streams.json

9) LICENSE (MIT)
MIT License

Copyright (c) 2025 Shahbaz Siddiqui

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...

10) scripts/run_all.sh (helper)
#!/usr/bin/env bash
# scripts/run_all.sh
# convenience script to run keygen, deploy, simulate

set -euo pipefail

echo "1) Generating keys (small, 3 per curve for quick test)..."
bash "$(dirname "$0")/generate_keys.sh" 3

echo "2) Deploying policies (mock)..."
python3 ../trust_engine/deploy_contracts.py

echo "3) Simulating rain (35 mm, 38C)..."
python3 ../trust_engine/simulate_rain.py --rain 35 --temp 38

echo "Done."
