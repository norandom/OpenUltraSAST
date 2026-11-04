def publish(request: object, store: object, policy: object) -> None:
    if policy.permits(request):
        store.publish(request)
