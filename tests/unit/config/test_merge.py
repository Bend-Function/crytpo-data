from crypto_collector.config.merge import merge_layers


def test_mappings_recurse_scalars_override_and_lists_replace() -> None:
    result = merge_layers(
        {"selection": {"top_n": 20, "quote_assets": ["USDT"]}},
        {"selection": {"top_n": 5, "quote_assets": ["USD", "USDT"]}},
    )

    assert result == {"selection": {"top_n": 5, "quote_assets": ["USD", "USDT"]}}


def test_merge_deep_copies_inputs() -> None:
    left = {"selection": {"quote_assets": ["USDT"]}}
    right = {"selection": {"top_n": 5}}

    result = merge_layers(left, right)
    result["selection"]["quote_assets"].append("USD")

    assert left == {"selection": {"quote_assets": ["USDT"]}}
    assert right == {"selection": {"top_n": 5}}
