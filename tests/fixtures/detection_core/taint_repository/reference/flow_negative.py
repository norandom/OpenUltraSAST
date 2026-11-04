def handle(value: str, effect: object) -> None:
    effect.write(value.strip())
