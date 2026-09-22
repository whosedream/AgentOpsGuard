class UpstreamTransportError(Exception):
    """Safe transport failure; the remote operation's outcome is unknown."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
