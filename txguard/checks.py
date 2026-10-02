"""The safety rules. Pure logic: outside data comes in through `scams` and `chain`."""

import re
import time
from dataclasses import dataclass

from .decoder import decode_calldata, is_unlimited

DANGER, WARNING, INFO, OK = "DANGER", "WARNING", "INFO", "OK"
_RANK = {OK: 0, INFO: 1, WARNING: 2, DANGER: 3}
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
NEW_ADDRESS_DAYS = 7


@dataclass
class Finding:
    level: str
    message: str


def verdict(findings: list) -> str:
    if not findings:
        return OK
    return max((f.level for f in findings), key=_RANK.__getitem__)


def check_address(address: str, scams: set, chain=None, role: str = "address") -> list:
    """Look at one address. `role` is how it is described in messages (e.g. "spender")."""
    if not ADDRESS_RE.match(address or ""):
        raise ValueError(f"Not a valid Ethereum address: {address!r}")
    a = address.lower()
    findings = []

    if a in scams:
        findings.append(Finding(DANGER, f"The {role} {address} is on a known scam list. Do not interact."))

    if chain is None:
        return findings

    if chain.is_contract(a):
        if chain.is_verified(a):
            findings.append(Finding(OK, f"The {role} is a contract with public, verified source code."))
        else:
            findings.append(Finding(WARNING, f"The {role} is a contract with UNVERIFIED code; nobody can easily see what it does."))

    first = chain.first_seen(a)
    if first is None:
        findings.append(Finding(WARNING, f"The {role} has no transaction history; it is brand new or unused."))
    else:
        days = (time.time() - first) / 86400
        if days < NEW_ADDRESS_DAYS:
            findings.append(Finding(WARNING, f"The {role} first appeared {days:.1f} days ago. Scam addresses are usually new."))
    return findings


def check_transaction(to: str, data: str, value: int, scams: set, chain=None) -> list:
    """Explain what a transaction will do and flag anything risky."""
    findings = check_address(to, scams, chain, role="destination")
    decoded = decode_calldata(data)

    if decoded is None:
        if value:
            findings.append(Finding(INFO, f"Plain ETH transfer of {value / 1e18:g} ETH to {to}."))
        return findings

    fn, args = decoded["function"], decoded["args"]

    if fn is None:
        findings.append(Finding(WARNING, f"Calls an unknown function ({decoded['selector']}). Can't explain what it does."))
    elif fn in ("approve", "increaseAllowance"):
        spender, amount = args
        if is_unlimited(amount):
            findings.append(Finding(DANGER, f"UNLIMITED approval: {spender} could take ALL of this token from your wallet, at any time, forever."))
        else:
            findings.append(Finding(INFO, f"Approves {spender} to spend up to {amount} units of the token at {to}."))
        findings += check_address(spender, scams, chain, role="spender")
    elif fn == "setApprovalForAll":
        operator, approved = args
        if approved:
            findings.append(Finding(DANGER, f"Gives {operator} control of EVERY NFT you own in collection {to}."))
            findings += check_address(operator, scams, chain, role="operator")
        else:
            findings.append(Finding(OK, f"Revokes {operator}'s access to collection {to}."))
    elif fn == "permit":
        owner, spender, amount = args[0], args[1], args[2]
        level = DANGER if is_unlimited(amount) else WARNING
        findings.append(Finding(level, f"Signature-based approval (permit) letting {spender} spend {'UNLIMITED' if level == DANGER else amount} tokens from {owner}."))
        findings += check_address(spender, scams, chain, role="spender")
    elif fn == "transfer":
        recipient, amount = args
        findings.append(Finding(INFO, f"Sends {amount} units of the token at {to} to {recipient}."))
        findings += check_address(recipient, scams, chain, role="recipient")
    elif fn == "transferFrom":
        sender, recipient, amount = args
        findings.append(Finding(INFO, f"Moves {amount} token units from {sender} to {recipient}."))
        findings += check_address(recipient, scams, chain, role="recipient")

    if value:
        findings.append(Finding(INFO, f"Also sends {value / 1e18:g} ETH."))
    return findings


# Functions whose approvals the decoder already explains, so the simulation shouldn't repeat them.
_DECODED_APPROVALS = {"approve", "increaseAllowance", "setApprovalForAll", "permit"}


def simulation_findings(sim, token_info, data: str = "0x") -> list:
    """Explain a Simulation (see simulate.py). `token_info(addr)` returns (symbol, decimals)."""
    from .simulate import format_amount, short

    if not sim.success:
        return [Finding(WARNING, f"Simulation says this transaction would FAIL ({sim.error}). You'd pay gas for nothing.")]

    decoded = decode_calldata(data)
    fn = decoded["function"] if decoded else None
    is_plain_send = decoded is None or fn in ("transfer", "transferFrom")
    findings = []

    lost = {t: d for t, d in sim.changes.items() if d < 0}
    gained = {t: d for t, d in sim.changes.items() if d > 0}
    for token, delta in lost.items():
        symbol, decimals = token_info(token)
        findings.append(Finding(INFO, f"Simulated result: you LOSE {format_amount(delta, decimals)} {symbol}."))
    for token, delta in gained.items():
        symbol, decimals = token_info(token)
        findings.append(Finding(OK, f"Simulated result: you RECEIVE {format_amount(delta, decimals)} {symbol}."))
    for collection, token_id in sim.nfts_out:
        findings.append(Finding(INFO, f"Simulated result: NFT #{token_id} from {short(collection)} LEAVES your wallet."))
    for collection, token_id in sim.nfts_in:
        findings.append(Finding(OK, f"Simulated result: you RECEIVE NFT #{token_id} from {short(collection)}."))

    if (lost or sim.nfts_out) and not (gained or sim.nfts_in) and not is_plain_send:
        findings.append(Finding(WARNING, "You give up assets and get NOTHING back. Fake 'claim' and 'mint' sites work exactly like this."))

    if fn not in _DECODED_APPROVALS:
        # Approvals hidden inside some other function (multicall, fake 'claim', etc.)
        for token, spender, amount in sim.approvals:
            symbol, decimals = token_info(token)
            if is_unlimited(amount):
                findings.append(Finding(DANGER, f"HIDDEN unlimited approval: {spender} could take ALL your {symbol}."))
            else:
                findings.append(Finding(WARNING, f"Hidden approval: {spender} may spend {format_amount(amount, decimals)} {symbol}."))
        for collection, operator in sim.approvals_for_all:
            findings.append(Finding(DANGER, f"HIDDEN 'approve all': {operator} gets every NFT in {short(collection)}."))

    if not findings:
        findings.append(Finding(OK, "Simulated result: nothing leaves your wallet."))
    return findings
