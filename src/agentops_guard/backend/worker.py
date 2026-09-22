"""RQ child-process initialization for the shared SQLAlchemy engine."""

from rq import Queue, Worker
from rq.job import Job

from agentops_guard.backend.database import engine


class DatabaseSafeWorker(Worker):
    def main_work_horse(self, job: Job, queue: Queue) -> None:
        # RQ invokes this only in the forked child, before preparing/running a
        # job. Replace its inherited pool without closing the parent's sockets.
        engine.dispose(close=False)
        super().main_work_horse(job, queue)
