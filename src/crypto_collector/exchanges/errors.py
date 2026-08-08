class ExchangeError(RuntimeError):
    """Base class for exchange-adapter failures."""


class ExchangeContractError(ExchangeError, ValueError):
    """An adapter or plan violated a frozen public-data contract."""


class AdapterNotRegisteredError(ExchangeError, LookupError):
    """No adapter is registered for the requested exchange."""
