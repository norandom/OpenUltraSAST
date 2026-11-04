def handle(value: str, effect: object, transform: object) -> None:
    effect.write(transform.apply(value))
