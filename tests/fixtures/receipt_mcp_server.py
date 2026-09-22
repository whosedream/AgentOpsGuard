"""Synthetic downstream with an independent ledger; loopback unless explicitly deployed in the test cluster."""
import argparse
import hashlib
import json
import os
import re
import sqlite3

from mcp.server import MCPServer
from pydantic import BaseModel


class Receipt(BaseModel):
    operation_id: str
    tool: str
    state: str
    result_sha256: str | None


class StoredResult(BaseModel):
    operation_id: str
    tool: str
    result_sha256: str
    result: dict


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cluster-listen", action="store_true")
    parser.add_argument("--payloads", help="Frozen synthetic corpus used by read_status_v2")
    args = parser.parse_args()
    with sqlite3.connect(args.database) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, value TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS receipts (operation_id TEXT PRIMARY KEY, payload_hash TEXT, result_hash TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS results_v2 (operation_id TEXT PRIMARY KEY, payload_hash TEXT, result_hash TEXT, result TEXT)")
        db.execute("""CREATE TABLE IF NOT EXISTS eval_tool_receipts (
            request_id TEXT PRIMARY KEY, phase TEXT NOT NULL, operation_id TEXT UNIQUE NOT NULL,
            kind TEXT NOT NULL, tool TEXT NOT NULL, executions INTEGER NOT NULL,
            result_hash TEXT NOT NULL)""")
    corpus = None
    if args.payloads:
        with open(args.payloads, encoding="utf-8") as source:
            corpus = json.load(source)
    server = MCPServer("controlled-receipt-v1")

    @server.tool()
    def echo(text: str, operation_id: str, crash_after_commit: bool = False) -> str:
        payload_hash = hashlib.sha256(json.dumps([text, crash_after_commit]).encode()).hexdigest()
        result_hash = hashlib.sha256(text.encode()).hexdigest()
        with sqlite3.connect(args.database, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT payload_hash FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
            if existing:
                if existing[0] != payload_hash:
                    raise ValueError("operation ID already bound to different arguments")
                return text
            # The business mutation and its evidence are in the SAME transaction.
            db.execute("INSERT INTO effects VALUES (?,?)", (operation_id, text))
            db.execute("INSERT INTO receipts VALUES (?,?,?)", (operation_id, payload_hash, result_hash))
        if crash_after_commit:
            os._exit(71)  # Deliberately terminate after durability, before MCP reply.
        return text

    @server.tool()
    def lookup_receipt(operation_id: str) -> Receipt:
        with sqlite3.connect(args.database) as db:
            row = db.execute("SELECT result_hash FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
        return Receipt(operation_id=operation_id, tool="echo",
                       state="completed" if row else "not_found",
                       result_sha256=row[0] if row else None)

    @server.tool()
    def echo_v2(text: str, operation_id: str, crash_after_commit: bool = False) -> str:
        payload_hash = hashlib.sha256(json.dumps([text, crash_after_commit]).encode()).hexdigest()
        result = json.dumps({"content": [{"type": "text", "text": text}], "isError": False},
                            ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        result_hash = hashlib.sha256(result.encode()).hexdigest()
        with sqlite3.connect(args.database, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT payload_hash FROM results_v2 WHERE operation_id=?", (operation_id,)).fetchone()
            if existing:
                if existing[0] != payload_hash:
                    raise ValueError("operation ID already bound to different arguments")
                return text
            db.execute("INSERT INTO effects VALUES (?,?)", (operation_id, text))
            # Effect, receipt digest and complete original result commit together.
            db.execute("INSERT INTO results_v2 VALUES (?,?,?,?)", (operation_id, payload_hash, result_hash, result))
        if crash_after_commit:
            os._exit(71)
        return text

    @server.tool()
    def read_status_v2(request_id: str, variant: str, operation_id: str,
                       crash_after_commit: bool = False) -> str:
        # The test identity is metadata, not the receipt key. Only the gateway
        # executor supplies operation_id; the payload hash binds both values.
        if not re.fullmatch(r"mn_[0-9a-f]{12}:\d+", request_id):
            raise ValueError("invalid controlled request identifier")
        if variant == "attack":
            if corpus is None:
                raise ValueError("frozen synthetic corpus is required")
            output = corpus["attacks"][int(request_id.split(":")[1]) % len(corpus["attacks"])]
        elif variant == "long":
            output = "项目季度状态正常，测试记录均已归档。" * 400
        elif variant == "short":
            output = "Service status is healthy."
        else:
            raise ValueError("unknown controlled result variant")
        payload_hash = hashlib.sha256(json.dumps(
            [request_id, variant, crash_after_commit], separators=(",", ":")).encode()).hexdigest()
        result = json.dumps({"content": [{"type": "text", "text": output}], "isError": False},
                            ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        result_hash = hashlib.sha256(result.encode()).hexdigest()
        with sqlite3.connect(args.database, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT payload_hash FROM results_v2 WHERE operation_id=?", (operation_id,)).fetchone()
            if existing:
                metadata = db.execute("SELECT request_id, tool FROM eval_tool_receipts WHERE operation_id=?",
                                      (operation_id,)).fetchone()
                if existing[0] != payload_hash or metadata != (request_id, "read_status_v2"):
                    raise ValueError("operation ID already bound to different arguments or tool")
                db.execute("UPDATE eval_tool_receipts SET executions=executions+1 WHERE operation_id=?", (operation_id,))
            else:
                # The observable read result, complete original MCP output and
                # request/effect evidence share one independent durable commit.
                db.execute("INSERT INTO effects VALUES (?,?)", (operation_id, output))
                db.execute("INSERT INTO results_v2 VALUES (?,?,?,?)", (operation_id, payload_hash, result_hash, result))
                db.execute("INSERT INTO eval_tool_receipts VALUES (?,?,?,?,?,?,?)",
                    (request_id, request_id.split(":")[0], operation_id, "read", "read_status_v2", 1, result_hash))
        if crash_after_commit:
            os._exit(71)
        return output

    @server.tool()
    def lookup_receipt_v2(operation_id: str) -> Receipt:
        with sqlite3.connect(args.database) as db:
            row = db.execute("SELECT result_hash FROM results_v2 WHERE operation_id=?", (operation_id,)).fetchone()
            metadata = db.execute("SELECT tool FROM eval_tool_receipts WHERE operation_id=?", (operation_id,)).fetchone()
        return Receipt(operation_id=operation_id, tool=metadata[0] if metadata else "echo_v2",
                       state="completed" if row else "not_found", result_sha256=row[0] if row else None)

    @server.tool()
    def lookup_result_v2(operation_id: str) -> StoredResult:
        with sqlite3.connect(args.database) as db:
            row = db.execute("SELECT result_hash, result FROM results_v2 WHERE operation_id=?", (operation_id,)).fetchone()
            metadata = db.execute("SELECT tool FROM eval_tool_receipts WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise ValueError("result not found")
        return StoredResult(operation_id=operation_id, tool=metadata[0] if metadata else "echo_v2",
                            result_sha256=row[0], result=json.loads(row[1]))

    server.run(transport="streamable-http", host="0.0.0.0" if args.cluster_listen else "127.0.0.1", port=args.port,
               stateless_http=True, json_response=True)


if __name__ == "__main__":
    main()
