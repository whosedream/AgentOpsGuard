from pathlib import Path
from typing import Optional

import typer
import uvicorn
import yaml
from redis.exceptions import RedisError
from rich import print
from rq import Queue, Worker

from agentops_guard.backend.database import SessionLocal, init_db
from agentops_guard.backend.schemas import EvalRunCreate, EvalSuiteCreate
from agentops_guard.backend.services.eval import create_eval_suite, run_eval
from agentops_guard.backend.services.jobs import redis_connection
from agentops_guard.backend.telemetry import configure_telemetry

app = typer.Typer(help="AgentOps Guard developer CLI")


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Run the FastAPI backend."""
    uvicorn.run("agentops_guard.backend.main:app", host=host, port=port, reload=reload)


@app.command()
def gateway(config: Optional[Path] = None, host: str = "127.0.0.1", port: int = 8001, reload: bool = False) -> None:
    """Run the MCP gateway."""
    from agentops_guard.gateway.app import load_gateway_config

    if config:
        init_db()
        db = SessionLocal()
        try:
            load_gateway_config(str(config), db)
        finally:
            db.close()
    uvicorn.run("agentops_guard.gateway.app:app", host=host, port=port, reload=reload)


@app.command("load-mcp-config")
def load_mcp_config(config: Path) -> None:
    """Load MCP gateway YAML into the registry."""
    from agentops_guard.gateway.app import load_gateway_config

    init_db()
    db = SessionLocal()
    try:
        load_gateway_config(str(config), db)
    finally:
        db.close()
    print(f"[green]Loaded MCP config:[/green] {config}")


@app.command("run-eval")
def run_eval_file(path: Path, project_id: str = "default") -> None:
    """Run an eval YAML/JSON file with built-in scanner and policy assertions."""
    init_db()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = data.get("cases", data if isinstance(data, list) else [])
    db = SessionLocal()
    try:
        suite = create_eval_suite(db, EvalSuiteCreate(project_id=project_id, name=data.get("name", path.stem), cases=cases))
        result = run_eval(db, EvalRunCreate(project_id=project_id, suite_id=suite.id))
        db.commit()
    finally:
        db.close()
    print(result.model_dump())


@app.command("worker")
def worker(queue: str = "default", burst: bool = False, with_scheduler: bool = False) -> None:
    """Run the Redis/RQ worker for AgentOps background jobs."""
    configure_telemetry("agentops-guard-worker")
    init_db()
    connection = redis_connection()
    try:
        connection.ping()
    except RedisError as exc:
        raise typer.Exit(f"Redis queue unavailable: {exc}") from exc
    worker_instance = Worker([Queue(queue, connection=connection)], connection=connection)
    worker_instance.work(burst=burst, with_scheduler=with_scheduler)
