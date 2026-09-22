"""Read-only PostgreSQL 16 aggregates. No SQL text, parameters, usernames or addresses."""
from sqlalchemy import text


def postgres_wait_snapshot(connection):
    waits = connection.execute(text("""
        SELECT state, wait_event_type, wait_event, count(*) AS sessions,
               max(extract(epoch FROM (clock_timestamp() - xact_start))) AS oldest_xact_seconds
        FROM pg_stat_activity
        WHERE datname = current_database() AND pid <> pg_backend_pid()
        GROUP BY state, wait_event_type, wait_event
        ORDER BY state, wait_event_type, wait_event
    """)).mappings().all()
    wal = connection.execute(text("""
        SELECT wal_records, wal_fpi, wal_bytes, wal_buffers_full, wal_write, wal_sync,
               wal_write_time, wal_sync_time, stats_reset::text FROM pg_stat_wal
    """)).mappings().one()
    database = connection.execute(text("""
        SELECT xact_commit, xact_rollback, deadlocks, blk_read_time, blk_write_time,
               temp_bytes, stats_reset::text FROM pg_stat_database WHERE datname = current_database()
    """)).mappings().one()
    settings = connection.execute(text("""
        SELECT current_setting('track_io_timing') AS track_io_timing,
               current_setting('track_wal_io_timing') AS track_wal_io_timing,
               current_setting('synchronous_commit') AS synchronous_commit
    """)).mappings().one()

    def numbers(row):
        return {k: float(v) if v is not None and not isinstance(v, (str, int, float)) else v
                for k, v in row.items()}

    return {"waits": [numbers(row) for row in waits], "wal": numbers(wal),
            "database": numbers(database), "settings": dict(settings),
            "sampling_not_exact_wait_duration": True}
