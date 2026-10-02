"""Dry-run a transaction against the real chain and report what would actually move.

Uses `eth_simulateV1` with `traceTransfers`, so plain ETH movements show up as
Transfer logs from a pseudo-address, alongside normal ERC-20 / NFT Transfer logs.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal

DEFAULT_RPC = {
    "mainnet": "https://ethereum-rpc.publicnode.com",
    "sepolia": "https://ethereum-sepolia-rpc.publicnode.com",
}

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
ETH_PSEUDO = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"


class RPCError(RuntimeError):
    pass


class RPC:
    def __init__(self, chain: str = "mainnet", url: str | None = None):
        self.url = url or os.environ.get("RPC_URL") or DEFAULT_RPC[chain]
        self._token_cache = {}

    def call(self, method: str, params: list):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json", "User-Agent": "tx-guard/0.2"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            reply = json.loads(resp.read().decode())
        if "error" in reply:
            err = reply["error"]
            raise RPCError(f"{err.get('message', err)} (code {err.get('code')})")
        return reply["result"]

    def token_info(self, address: str):
        """(symbol, decimals) for a token, with safe fallbacks."""
        if address == ETH_PSEUDO:
            return "ETH", 18
        if address not in self._token_cache:
            symbol, decimals = short(address), 0
            try:
                decimals = int(self.call("eth_call", [{"to": address, "data": "0x313ce567"}, "latest"]), 16)
            except Exception:
                pass
            try:
                symbol = decode_symbol(self.call("eth_call", [{"to": address, "data": "0x95d89b41"}, "latest"])) or symbol
            except Exception:
                pass
            self._token_cache[address] = (symbol, decimals)
        return self._token_cache[address]


def short(address: str) -> str:
    return address[:6] + "…" + address[-4:]


def decode_symbol(hex_data: str) -> str:
    """Token symbols come back as an ABI string or, on old tokens, as bytes32."""
    raw = bytes.fromhex(hex_data[2:])
    if len(raw) >= 96:
        length = int.from_bytes(raw[32:64], "big")
        text = raw[64:64 + length]
    else:
        text = raw[:32].rstrip(b"\x00")
    return text.decode("utf-8", "ignore").strip()


def topic_address(topic: str) -> str:
    return "0x" + topic[-40:].lower()


@dataclass
class Simulation:
    success: bool
    error: str | None = None
    changes: dict = field(default_factory=dict)      # token -> net change for the signer
    nfts_out: list = field(default_factory=list)     # (collection, token_id)
    nfts_in: list = field(default_factory=list)
    approvals: list = field(default_factory=list)    # (token, spender, amount)
    approvals_for_all: list = field(default_factory=list)  # (collection, operator)


def parse_simulation(result: list, owner: str) -> Simulation:
    """Turn a raw eth_simulateV1 result into what the signer gains, loses and approves."""
    owner = owner.lower()
    call = result[0]["calls"][0]
    if call.get("status") != "0x1":
        err = call.get("error") or {}
        return Simulation(success=False, error=err.get("message", "transaction reverted"))

    sim = Simulation(success=True)
    for log in call.get("logs", []):
        topics = [t.lower() for t in log.get("topics", [])]
        token = log["address"].lower()
        if not topics:
            continue
        if topics[0] == TRANSFER and len(topics) == 3:          # ERC-20 or native ETH
            src, dst = topic_address(topics[1]), topic_address(topics[2])
            amount = int(log.get("data", "0x0") or "0x0", 16)
            if src == owner:
                sim.changes[token] = sim.changes.get(token, 0) - amount
            if dst == owner:
                sim.changes[token] = sim.changes.get(token, 0) + amount
        elif topics[0] == TRANSFER and len(topics) == 4:        # NFT (ERC-721)
            src, dst, token_id = topic_address(topics[1]), topic_address(topics[2]), int(topics[3], 16)
            if src == owner:
                sim.nfts_out.append((token, token_id))
            if dst == owner:
                sim.nfts_in.append((token, token_id))
        elif topics[0] == APPROVAL and len(topics) == 3 and topic_address(topics[1]) == owner:
            sim.approvals.append((token, topic_address(topics[2]), int(log.get("data", "0x0") or "0x0", 16)))
        elif topics[0] == APPROVAL_FOR_ALL and topic_address(topics[1]) == owner:
            if int(log.get("data", "0x0") or "0x0", 16):
                sim.approvals_for_all.append((token, topic_address(topics[2])))

    sim.changes = {t: d for t, d in sim.changes.items() if d != 0}
    return sim


def simulate(rpc: RPC, sender: str, to: str, data: str, value: int) -> Simulation:
    call = {"from": sender, "to": to, "data": data or "0x", "value": hex(value)}
    result = rpc.call("eth_simulateV1", [{"blockStateCalls": [{"calls": [call]}], "traceTransfers": True}, "latest"])
    return parse_simulation(result, sender)


def format_amount(raw: int, decimals: int) -> str:
    value = Decimal(abs(raw)) / (Decimal(10) ** decimals)
    text = f"{value:,.6f}".rstrip("0").rstrip(".")
    return text if text not in ("", "0") else f"{value:.2E}"
