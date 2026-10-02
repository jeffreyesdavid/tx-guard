"""Decode transaction calldata for the token functions scammers abuse most."""

MAX_UINT256 = 2**256 - 1
# Anything at or above this is treated as "unlimited" (some drainers use 2**255 etc.)
UNLIMITED_THRESHOLD = 2**255

SELECTORS = {
    "0x095ea7b3": ("approve", ["address", "uint256"]),
    "0x39509351": ("increaseAllowance", ["address", "uint256"]),
    "0xa22cb465": ("setApprovalForAll", ["address", "bool"]),
    "0xa9059cbb": ("transfer", ["address", "uint256"]),
    "0x23b872dd": ("transferFrom", ["address", "address", "uint256"]),
    "0xd505accf": ("permit", ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"]),
}


def _word(data_hex: str, index: int) -> str:
    start = index * 64
    word = data_hex[start:start + 64]
    if len(word) != 64:
        raise ValueError("calldata is too short for this function")
    return word


def _decode(kind: str, word: str):
    if kind == "address":
        return "0x" + word[-40:]
    if kind == "bool":
        return int(word, 16) != 0
    if kind in ("uint256", "uint8"):
        return int(word, 16)
    return "0x" + word


def decode_calldata(data: str):
    """Return {"function", "args"} for known selectors, or None if unknown / empty."""
    if not data or data in ("0x", "0x0"):
        return None
    data = data.lower()
    if not data.startswith("0x"):
        data = "0x" + data
    selector, body = data[:10], data[10:]
    if selector not in SELECTORS:
        return {"function": None, "selector": selector, "args": []}
    name, types = SELECTORS[selector]
    args = [_decode(t, _word(body, i)) for i, t in enumerate(types)]
    return {"function": name, "selector": selector, "args": args}


def is_unlimited(amount: int) -> bool:
    return amount >= UNLIMITED_THRESHOLD
