def publish(request: object, store: object, allowed: bool) -> None:
    if allowed:
        store.publish(request)
