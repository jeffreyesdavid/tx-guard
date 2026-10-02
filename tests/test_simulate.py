import unittest

from txguard.checks import DANGER, INFO, OK, WARNING, simulation_findings, verdict
from txguard.decoder import MAX_UINT256
from txguard.simulate import (APPROVAL, APPROVAL_FOR_ALL, ETH_PSEUDO, TRANSFER,
                              decode_symbol, format_amount, parse_simulation)

ME = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
THIEF = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
NFT = "0xcccccccccccccccccccccccccccccccccccccccc"
TOKENS = {USDC: ("USDC", 6), ETH_PSEUDO: ("ETH", 18), NFT: ("APE", 0)}


def topic(addr):
    return "0x" + addr[2:].rjust(64, "0")


def log(address, *topics, data="0x"):
    return {"address": address, "topics": list(topics), "data": data}


def result(*logs, status="0x1", error=None):
    call = {"status": status, "logs": list(logs)}
    if error:
        call["error"] = {"message": error}
    return [{"calls": [call]}]


def usdc_transfer(src, dst, amount):
    return log(USDC, TRANSFER, topic(src), topic(dst), data=hex(amount))


def findings_for(raw, data="0x"):
    return simulation_findings(parse_simulation(raw, ME), TOKENS.__getitem__, data)


class TestParse(unittest.TestCase):
    def test_net_changes(self):
        sim = parse_simulation(result(usdc_transfer(ME, THIEF, 500_000_000),
                                      log(ETH_PSEUDO, TRANSFER, topic(THIEF), topic(ME), data=hex(10**17))), ME)
        self.assertEqual(sim.changes, {USDC: -500_000_000, ETH_PSEUDO: 10**17})

    def test_other_peoples_transfers_ignored(self):
        sim = parse_simulation(result(usdc_transfer(THIEF, NFT, 5)), ME)
        self.assertEqual(sim.changes, {})

    def test_revert(self):
        sim = parse_simulation(result(status="0x0", error="execution reverted"), ME)
        self.assertFalse(sim.success)
        self.assertEqual(sim.error, "execution reverted")

    def test_nft_transfer(self):
        sim = parse_simulation(result(log(NFT, TRANSFER, topic(ME), topic(THIEF), hex(42))), ME)
        self.assertEqual(sim.nfts_out, [(NFT, 42)])


class TestFindings(unittest.TestCase):
    def test_lose_usdc_shows_human_amount(self):
        f = findings_for(result(usdc_transfer(ME, THIEF, 500_000_000)))
        self.assertTrue(any("LOSE 500 USDC" in x.message for x in f))

    def test_swap_is_fine(self):
        f = findings_for(result(usdc_transfer(ME, THIEF, 100_000_000),
                                log(ETH_PSEUDO, TRANSFER, topic(THIEF), topic(ME), data=hex(3 * 10**16))),
                         data="0xdeadbeef")
        self.assertEqual(verdict(f), INFO)
        self.assertTrue(any("RECEIVE 0.03 ETH" in x.message for x in f))

    def test_fake_claim_takes_and_gives_nothing(self):
        f = findings_for(result(usdc_transfer(ME, THIEF, 1_000_000)), data="0xdeadbeef")
        self.assertEqual(verdict(f), WARNING)

    def test_plain_transfer_is_not_flagged_as_getting_nothing(self):
        data = "0xa9059cbb" + topic(THIEF)[2:] + format(5, "064x")
        f = findings_for(result(usdc_transfer(ME, THIEF, 5)), data=data)
        self.assertEqual(verdict(f), INFO)

    def test_hidden_unlimited_approval(self):
        f = findings_for(result(log(USDC, APPROVAL, topic(ME), topic(THIEF), data=hex(MAX_UINT256))), data="0xdeadbeef")
        self.assertEqual(verdict(f), DANGER)

    def test_hidden_approve_all(self):
        f = findings_for(result(log(NFT, APPROVAL_FOR_ALL, topic(ME), topic(THIEF), data=hex(1))), data="0xdeadbeef")
        self.assertEqual(verdict(f), DANGER)

    def test_would_fail(self):
        self.assertEqual(verdict(findings_for(result(status="0x0", error="reverted"))), WARNING)

    def test_nothing_moves(self):
        self.assertEqual(verdict(findings_for(result())), OK)


class TestHelpers(unittest.TestCase):
    def test_format_amount(self):
        self.assertEqual(format_amount(-500_000_000, 6), "500")
        self.assertEqual(format_amount(1_234_567_890_000_000_000, 18), "1.234568")

    def test_symbol_abi_string(self):
        encoded = "0x" + format(32, "064x") + format(4, "064x") + b"USDC".hex().ljust(64, "0")
        self.assertEqual(decode_symbol(encoded), "USDC")

    def test_symbol_bytes32(self):
        self.assertEqual(decode_symbol("0x" + b"MKR".hex().ljust(64, "0")), "MKR")


if __name__ == "__main__":
    unittest.main()
