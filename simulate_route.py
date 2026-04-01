# simulate_route.py
# Add to main.py:
#   from simulate_route import router as simulate_router
#   app.include_router(simulate_router)

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict
from simulate import run_simulation

router = APIRouter()


class SimulateRequest(BaseModel):
    scan_result: Dict[str, Any]   # full scan JSON — no repo_path needed


@router.post("/simulate")
async def simulate_attack(req: SimulateRequest):
    """
    Red-team simulation — runs entirely from scan JSON.
    No filesystem access, no repo_path required.
    Returns SimulationReport consumed by simulation.html.
    """
    try:
        return run_simulation(req.scan_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))