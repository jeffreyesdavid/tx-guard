import time
import unittest

from txguard.checks import DANGER, INFO, OK, WARNING, check_address, check_transaction, verdict
from txguard.decoder import MAX_UINT256, decode_calldata

SCAMMER = "0x101ce0cedd142f199c9ef61739ae59b6611a0fc0"   # from the ScamSniffer list
FRIEND = "0x1111111111111111111111111111111111111111"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"     # USDC contract
SCAMS = {SCAMMER}


def word(x) -> str:
    if isinstance(x, str):
        return x[2:].lower().rjust(64, "0")
    return format(int(x), "064x")


def calldata(selector, *args):
    return selector + "".join(word(a) for a in args)


class FakeChain:
    """Stands in for Etherscan so tests run offline."""

    def __init__(self, contracts=(), unverified=(), ages_days=None):
        self.contracts, self.unverified = set(contracts), set(unverified)
        self.ages = ages_days or {}

    def is_contract(self, a): return a in self.contracts
    def is_verified(self, a): return a not in self.unverified

    def first_seen(self, a):
        days = self.ages.get(a, 365)
        return None if days is None else time.time() - days * 86400


class TestDecoder(unittest.TestCase):
    def test_approve(self):
        d = decode_calldata(calldata("0x095ea7b3", FRIEND, 500))
        self.assertEqual(d["function"], "approve")
        self.assertEqual(d["args"], [FRIEND, 500])

    def test_empty(self):
        self.assertIsNone(decode_calldata("0x"))

    def test_unknown_selector(self):
        self.assertIsNone(decode_calldata("0xdeadbeef")["function"])

    def test_truncated(self):
        with self.assertRaises(ValueError):
            decode_calldata("0x095ea7b3" + "00" * 10)


class TestAddress(unittest.TestCase):
    def test_scam_address(self):
        self.assertEqual(verdict(check_address(SCAMMER, SCAMS)), DANGER)

    def test_scam_match_ignores_case(self):
        self.assertEqual(verdict(check_address(SCAMMER.upper().replace("0X", "0x"), SCAMS)), DANGER)

    def test_clean_address(self):
        self.assertEqual(verdict(check_address(FRIEND, SCAMS)), OK)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            check_address("0x123", SCAMS)

    def test_unverified_contract(self):
        chain = FakeChain(contracts={FRIEND}, unverified={FRIEND})
        self.assertEqual(verdict(check_address(FRIEND, SCAMS, chain)), WARNING)

    def test_brand_new_address(self):
        chain = FakeChain(ages_days={FRIEND: 2})
        self.assertEqual(verdict(check_address(FRIEND, SCAMS, chain)), WARNING)

    def test_never_used(self):
        chain = FakeChain(ages_days={FRIEND: None})
        self.assertEqual(verdict(check_address(FRIEND, SCAMS, chain)), WARNING)


class TestTransaction(unittest.TestCase):
    def test_unlimited_approval_is_danger(self):
        data = calldata("0x095ea7b3", FRIEND, MAX_UINT256)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), DANGER)

    def test_small_approval_is_info(self):
        data = calldata("0x095ea7b3", FRIEND, 100)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), INFO)

    def test_approval_to_scammer_is_danger(self):
        data = calldata("0x095ea7b3", SCAMMER, 100)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), DANGER)

    def test_nft_approve_all_is_danger(self):
        data = calldata("0xa22cb465", FRIEND, 1)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), DANGER)

    def test_nft_revoke_is_ok(self):
        data = calldata("0xa22cb465", FRIEND, 0)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), OK)

    def test_transfer_to_scammer(self):
        data = calldata("0xa9059cbb", SCAMMER, 10)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), DANGER)

    def test_unknown_function_warns(self):
        self.assertEqual(verdict(check_transaction(TOKEN, "0xdeadbeef", 0, SCAMS)), WARNING)

    def test_plain_eth_send(self):
        self.assertEqual(verdict(check_transaction(FRIEND, "0x", 10**18, SCAMS)), INFO)

    def test_unlimited_permit_is_danger(self):
        data = calldata("0xd505accf", FRIEND, SCAMMER, MAX_UINT256, 0, 27, "0x" + "00" * 32, "0x" + "00" * 32)
        self.assertEqual(verdict(check_transaction(TOKEN, data, 0, SCAMS)), DANGER)


if __name__ == "__main__":
    unittest.main()
