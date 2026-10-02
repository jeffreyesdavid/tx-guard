"""Command line: `python -m txguard address|tx|hash ...`"""

import argparse
import sys

from .checks import DANGER, INFO, OK, WARNING, Finding, check_address, check_transaction, simulation_findings, verdict
from .simulate import RPC, RPCError, simulate
from .sources import CHAINS, Etherscan, load_scam_list

ICONS = {DANGER: "🚨", WARNING: "⚠️ ", INFO: "ℹ️ ", OK: "✅"}
SUMMARY = {
    DANGER: "DO NOT SIGN. This looks dangerous.",
    WARNING: "Be careful. Double-check before signing.",
    INFO: "Nothing alarming found.",
    OK: "Nothing alarming found.",
}


def print_report(findings):
    if not findings:
        print(f"  {ICONS[OK]} OK       No red flags found.")
    for f in findings:
        print(f"  {ICONS[f.level]} {f.level:<8} {f.message}")
    level = verdict(findings)
    print(f"\n  Verdict: {ICONS[level]} {SUMMARY[level]}")
    return level


def run_simulation(args):
    rpc = RPC(chain=args.chain)
    try:
        sim = simulate(rpc, args.sender, args.to, args.data, args.value)
    except RPCError as e:
        return [Finding(WARNING, f"Simulation unavailable: {e}. Try another node with RPC_URL (e.g. a free Alchemy URL).")]
    except Exception as e:
        return [Finding(WARNING, f"Simulation unavailable (couldn't reach {rpc.url}): {e}")]
    return simulation_findings(sim, rpc.token_info, args.data)


def main(argv=None):
    p = argparse.ArgumentParser(prog="txguard", description="Check a crypto address or transaction before you sign.")
    p.add_argument("--chain", choices=CHAINS, default="mainnet")
    p.add_argument("--offline", action="store_true", help="Scam list + decoding only; skip Etherscan lookups")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("address", help="Check one address")
    a.add_argument("address")

    t = sub.add_parser("tx", help="Check a transaction you are about to sign")
    t.add_argument("--to", required=True)
    t.add_argument("--data", default="0x")
    t.add_argument("--value", type=int, default=0, help="ETH value in wei")
    t.add_argument("--from", dest="sender", help="Your wallet address; turns on simulation of what you'd gain/lose")

    h = sub.add_parser("hash", help="Check an existing transaction by its hash")
    h.add_argument("tx_hash")

    args = p.parse_args(argv)
    scams = load_scam_list()
    if not scams:
        print("  ⚠️  Could not load the scam list; that check is skipped.\n")

    chain = None
    if not args.offline:
        try:
            chain = Etherscan(chain=args.chain)
        except RuntimeError as e:
            if args.cmd == "hash":
                sys.exit(f"Error: {e}")
            print(f"  ℹ️  {e}. Running offline checks only.\n")

    try:
        if args.cmd == "address":
            findings = check_address(args.address, scams, chain)
        elif args.cmd == "tx":
            findings = check_transaction(args.to, args.data, args.value, scams, chain)
            if args.sender and not args.offline:
                check_address(args.sender, set())  # validates the format
                findings += run_simulation(args)
        else:
            tx = chain.get_transaction(args.tx_hash)
            findings = check_transaction(tx["to"], tx["data"], tx["value"], scams, chain)
    except (ValueError, RuntimeError) as e:
        sys.exit(f"Error: {e}")

    level = print_report(findings)
    sys.exit(2 if level == DANGER else 1 if level == WARNING else 0)


if __name__ == "__main__":
    main()
