"""Windows-compatible Redis worker. Run with: python worker.py"""
import os
from rq.worker import SimpleWorker
from redis import Redis
from rq.timeouts import TimerDeathPenalty
from prometheus_client import start_http_server
from observability import configure_json_logging
from config import settings

if __name__ == "__main__":
    configure_json_logging()
    start_http_server(int(os.environ.get("SECUREMAILSCOPE_WORKER_METRICS_PORT", "9100")))
    worker = SimpleWorker(["analysis"], connection=Redis.from_url(settings.redis_url))
    worker.death_penalty_class = TimerDeathPenalty
    worker.work()
