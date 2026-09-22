from concurrent.futures import ThreadPoolExecutor
import time

from sqlalchemy import text

from test_database_resilience import postgres_url as postgres_url, database
from agentops_guard.backend.database_diagnostics import postgres_wait_snapshot


def test_real_lock_wait_is_visible_without_sql_or_parameters(postgres_url):
    with (database(postgres_url) as engine, database(postgres_url) as waiting_engine,
          database(postgres_url) as observing_engine):
        with engine.begin() as db:
            db.execute(text("CREATE TABLE diagnostic_private_probe (id integer PRIMARY KEY, value integer)"))
            db.execute(text("INSERT INTO diagnostic_private_probe VALUES (1, 0)"))
        holder = engine.connect()
        holder.execute(text("UPDATE diagnostic_private_probe SET value=value+1 WHERE id=1"))

        def wait_for_lock():
            with waiting_engine.begin() as db:
                db.execute(text("SET LOCAL lock_timeout = '5s'"))
                db.execute(text("SET LOCAL statement_timeout = '5s'"))
                db.execute(text("UPDATE diagnostic_private_probe SET value=value+1 WHERE id=1"))

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiter = pool.submit(wait_for_lock)
                observed = False
                try:
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        with observing_engine.connect() as db:
                            snapshot = postgres_wait_snapshot(db)
                        assert "diagnostic_private_probe" not in str(snapshot)
                        assert "UPDATE" not in str(snapshot)
                        if any(row["wait_event_type"] == "Lock" for row in snapshot["waits"]):
                            observed = True
                            break
                        time.sleep(.01)
                finally:
                    holder.commit()
                waiter.result(timeout=5)
                assert observed
                assert snapshot["sampling_not_exact_wait_duration"]
                assert {"wal_sync", "wal_sync_time", "stats_reset"} <= snapshot["wal"].keys()
        finally:
            holder.close()
