"""Outside data: the ScamSniffer blocklist and the Etherscan API (v2)."""

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

SCAM_LIST_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
CACHE_FILE = Path.home() / ".txguard" / "scam_addresses.json"
CACHE_MAX_AGE = 24 * 3600  # refresh once a day

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"
CHAINS = {"mainnet": 1, "sepolia": 11155111}


def _get_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": "tx-guard/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_scam_list(refresh: bool = False) -> set:
    """Download (or read the cached) list of known scam addresses, lowercased."""
    fresh = CACHE_FILE.exists() and time.time() - CACHE_FILE.stat().st_mtime < CACHE_MAX_AGE
    if fresh and not refresh:
        return set(json.loads(CACHE_FILE.read_text()))
    try:
        addresses = [a.lower() for a in _get_json(SCAM_LIST_URL)]
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(addresses))
        return set(addresses)
    except Exception:
        if CACHE_FILE.exists():  # offline: fall back to an old copy
            return set(json.loads(CACHE_FILE.read_text()))
        return set()


class Etherscan:
    def __init__(self, api_key: str | None = None, chain: str = "mainnet"):
        self.api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")
        if not self.api_key:
            raise RuntimeError("Set ETHERSCAN_API_KEY (free key at https://etherscan.io/myapikey)")
        self.chain_id = CHAINS[chain]

    def _call(self, **params):
        params.update(chainid=self.chain_id, apikey=self.api_key)
        return _get_json(ETHERSCAN_URL + "?" + urllib.parse.urlencode(params))

    def is_contract(self, address: str) -> bool:
        code = self._call(module="proxy", action="eth_getCode", address=address, tag="latest").get("result", "0x")
        return code not in ("0x", "0x0", None)

    def is_verified(self, address: str) -> bool:
        result = self._call(module="contract", action="getsourcecode", address=address).get("result") or [{}]
        return bool(result[0].get("SourceCode"))

    def first_seen(self, address: str):
        """Unix timestamp of the address's first transaction, or None if it has none."""
        data = self._call(module="account", action="txlist", address=address,
                          startblock=0, endblock=99999999, page=1, offset=1, sort="asc")
        txs = data.get("result")
        if isinstance(txs, list) and txs:
            return int(txs[0]["timeStamp"])
        return None

    def get_transaction(self, tx_hash: str) -> dict:
        tx = self._call(module="proxy", action="eth_getTransactionByHash", txhash=tx_hash).get("result")
        if not tx:
            raise RuntimeError(f"Transaction {tx_hash} not found on this chain")
        return {"to": tx.get("to"), "data": tx.get("input"), "value": int(tx.get("value", "0x0"), 16)}
