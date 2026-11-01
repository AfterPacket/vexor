"""Bounded, cancellation-safe orchestration without provider or payload logic."""
import asyncio


async def bounded_as_completed(items, worker, *, limit=16, active_tasks=None,
                               local_tasks=None, should_stop=lambda: False):
    """Yield completed Tasks, scheduling at most `limit` lazy work items.

    Workers are invoked only when a slot is available. On cancellation or early
    iterator close, every owned task is cancelled and drained before returning.
    The caller consumes task.result(), including errors, explicitly.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("Task limit must be a positive integer")
    iterator = iter(items)
    owned = set()
    exhausted = False
    try:
        while True:
            while not exhausted and not should_stop() and len(owned) < limit:
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                task = asyncio.create_task(worker(item))
                owned.add(task)
                if active_tasks is not None:
                    active_tasks.add(task)
                if local_tasks is not None:
                    local_tasks.add(task)
            if should_stop():
                for task in owned:
                    task.cancel()
            if not owned:
                break
            done, _ = await asyncio.wait(owned, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                owned.remove(task)
                if active_tasks is not None:
                    active_tasks.discard(task)
                if local_tasks is not None:
                    local_tasks.discard(task)
                yield task
    finally:
        for task in owned:
            task.cancel()
        await asyncio.gather(*owned, return_exceptions=True)
        if active_tasks is not None:
            active_tasks.difference_update(owned)
        if local_tasks is not None:
            local_tasks.difference_update(owned)
