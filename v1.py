from typing import List, Dict, Any, Generator
from pydantic import BaseModel
import json
from datetime import datetime

class Pipeline:
    class Valves(BaseModel):
        LOG_LEVEL: str = "INFO"

    def __init__(self):
        self.valves = self.Valves()

    async def on_startup(self):
        pass

    async def on_shutdown(self):
        pass

    def process_hunt_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        hunt_data = {
            "apt_set": data.get("apt_set", []),
            "mitre_techniques": data.get("mitre_techniques", []),
            "iocs": data.get("iocs", []),
            "region": data.get("region", ""),
            "hunt_type": data.get("hunt_type", ""),
            "objectives": data.get("objectives", []),
            "timeframe": data.get("timeframe", {}),
            "critical_asset": data.get("critical_asset", []),
            "log_sources": data.get("log_sources", []),
            "compliance": data.get("compliance", []),
            "industry": data.get("industry", ""),
            "environment": data.get("environment", ""),
            "timestamp": datetime.utcnow().isoformat()
        }

        return {
            "jsonrpc": "2.0",
            "method": "process_hunt_plan",
            "params": hunt_data,
            "id": 1
        }

    def pipe(self, prompt: str = None, **kwargs) -> Generator[str, None, None]:
        try:
            data = json.loads(prompt) if prompt else kwargs
            result = self.process_hunt_results(data)
            yield json.dumps(result, indent=2)
        except Exception as e:
            yield f"Error: {str(e)}"

    def run(self, prompt: str, **kwargs) -> List[Dict[str, Any]]:
        results = list(self.pipe(prompt=prompt, **kwargs))
        return [{"text": "".join(results)}]
