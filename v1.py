import json
from datetime import datetime
from typing import List, Dict, Any

def process_hunt_results(
   apt_set: List[str],
   mitre_techniques: List[str], 
   iocs: List[str],
   region: str,
   hunt_type: str,
   objectives: List[str],
   timeframe: Dict[str, str],
   critical_asset: List[str],
   log_sources: List[str],
   compliance: List[str],
   industry: str,
   environment: str
) -> Dict[str, Any]:
   
   if not all([apt_set, mitre_techniques, iocs, region, hunt_type, objectives, 
               timeframe, critical_asset, log_sources, compliance, industry, environment]):
       raise ValueError("All input parameters are required")
       
   timestamp = datetime.utcnow().isoformat()
   
   hunt_data = {
       "apt_set": apt_set,
       "mitre_techniques": mitre_techniques,
       "iocs": iocs,
       "region": region,
       "hunt_type": hunt_type,
       "objectives": objectives,
       "timeframe": timeframe,
       "critical_asset": critical_asset,
       "log_sources": log_sources,
       "compliance": compliance,
       "industry": industry,
       "environment": environment,
       "timestamp": timestamp
   }
   
   jsonrpc_payload = {
       "jsonrpc": "2.0",
       "method": "process_hunt_plan",
       "params": hunt_data,
       "id": 1
   }
   
   print("\nJSON-RPC 2.0 Payload:")
   print(json.dumps(jsonrpc_payload, indent=2))
   
   return jsonrpc_payload

if __name__ == "__main__":
   test_data = {
       "apt_set": ["APT28", "APT29"],
       "mitre_techniques": ["T1190", "T1566", "T1595"],
       "iocs": ["1.2.3.4", "malware.exe", "evil.dll"],
       "region": "EMEA",
       "hunt_type": "targeted",
       "objectives": ["detect_lateral_movement", "identify_data_exfil"],
       "timeframe": {"start": "2024-01-01", "end": "2024-03-19"},
       "critical_asset": ["domain_controllers", "file_servers"],
       "log_sources": ["windows_events", "firewall_logs", "proxy_logs"],
       "compliance": ["NIST", "ISO27001"],
       "industry": "finance",
       "environment": "hybrid"
   }
   
   try:
       result = process_hunt_results(**test_data)
   except Exception as e:
       print(f"Error processing hunt results: {str(e)}")
