from __future__ import annotations

from crypto_collector.selection.models import CatalogScope, CatalogView
from crypto_collector.selection.selector import ResolvedFixedSelection


class FixedPairResolutionError(ValueError):
    def __init__(
        self,
        *,
        scope: CatalogScope,
        request: str,
        candidate_keys: tuple[str, ...],
        reason: str,
    ) -> None:
        self.scope = scope
        self.request = request
        self.candidate_keys = candidate_keys
        self.reason = reason
        candidates = ", ".join(repr(item) for item in candidate_keys) or "none"
        super().__init__(
            f"fixed request {request!r} could not resolve in "
            f"{scope.exchange.value}/{scope.market.value}: {reason}; "
            f"candidate keys: {candidates}"
        )


def _requests(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError("fixed requests must be a tuple")
    normalized: list[str] = []
    identities: set[str] = set()
    for item in value:
        if type(item) is not str:
            raise TypeError("fixed requests must contain strings")
        if not item or item != item.strip():
            raise ValueError("fixed requests must be non-blank normalized strings")
        identity = item.casefold()
        if identity in identities:
            raise ValueError("fixed requests must be unique under case-folding")
        identities.add(identity)
        normalized.append(item)
    return tuple(normalized)


def resolve_fixed_requests(
    requests: tuple[str, ...],
    catalog: CatalogView,
) -> ResolvedFixedSelection:
    normalized_requests = _requests(requests)
    if type(catalog) is not CatalogView:
        raise TypeError("catalog must be CatalogView")
    if catalog.catalog_revision <= 0:
        raise ValueError("fixed requests require a complete catalog revision")

    by_key = {item.instrument_key: item for item in catalog.instruments}
    selected: set[str] = set()
    for request in normalized_requests:
        exact = by_key.get(request)
        if exact is not None:
            if not exact.present or not exact.tradable:
                raise FixedPairResolutionError(
                    scope=catalog.scope,
                    request=request,
                    candidate_keys=(exact.instrument_key,),
                    reason="exact instrument key is not present and tradable",
                )
            selected.add(exact.instrument_key)
            continue

        pair_candidates = tuple(
            sorted(
                (
                    item
                    for item in catalog.instruments
                    if item.canonical_pair == request
                ),
                key=lambda item: item.instrument_key,
            )
        )
        eligible = tuple(
            item for item in pair_candidates if item.present and item.tradable
        )
        if len(eligible) != 1:
            reason = (
                "canonical pair has no present tradable match"
                if not eligible
                else "canonical pair is ambiguous"
            )
            raise FixedPairResolutionError(
                scope=catalog.scope,
                request=request,
                candidate_keys=tuple(item.instrument_key for item in pair_candidates),
                reason=reason,
            )
        selected.add(eligible[0].instrument_key)

    return ResolvedFixedSelection(
        scope=catalog.scope,
        catalog_revision=catalog.catalog_revision,
        instrument_keys=frozenset(selected),
    )


__all__ = ["FixedPairResolutionError", "resolve_fixed_requests"]
