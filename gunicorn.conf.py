"""Gunicorn hooks — start monitors and the weekly report scheduler in each worker."""


def post_worker_init(worker):
    from app import ensure_runtime_started

    ensure_runtime_started()
