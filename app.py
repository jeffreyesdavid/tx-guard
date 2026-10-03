"""Web demo for tx-guard. Run locally: streamlit run app.py"""

import os

import streamlit as st

from txguard.checks import DANGER, INFO, OK, WARNING, check_address, check_transaction, verdict
from txguard.sources import Etherscan, load_scam_list

st.set_page_config(page_title="tx-guard: check before you sign", page_icon="🛡️")

EXAMPLES = {
    "Unlimited USDC approval": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    "NFT 'approve all'": ("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        "0xa22cb4650000000000000000000000003333333333333333333333333333333333333333"
        "0000000000000000000000000000000000000000000000000000000000000001"),
    "Normal 500 USDC approval": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0x095ea7b30000000000000000000000002222222222222222222222222222222222222222"
        "000000000000000000000000000000000000000000000000000000001dcd6500"),
}
SHOW = {DANGER: st.error, WARNING: st.warning, INFO: st.info, OK: st.success}
VERDICT = {DANGER: "🚨 DO NOT SIGN. This looks dangerous.", WARNING: "⚠️ Be careful. Double-check before signing.",
           INFO: "✅ Nothing alarming found.", OK: "✅ Nothing alarming found."}


@st.cache_data(ttl=24 * 3600, show_spinner="Loading scam address list…")
def scams():
    return load_scam_list()


def chain():
    """Etherscan client if a key is set (env var or Streamlit secrets), else None (offline checks only)."""
    key = os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        try:
            key = st.secrets.get("ETHERSCAN_API_KEY")
        except Exception:
            key = None
    return Etherscan(api_key=key) if key else None


def report(findings):
    for f in findings:
        SHOW[f.level](f.message)
    level = verdict(findings)
    st.subheader(VERDICT[level])


st.title("🛡️ tx-guard")
st.markdown("**Check a crypto transaction before you sign it.** Paste what your wallet is about to sign, "
            "and tx-guard explains it in plain English and flags scams. "
            "[Source on GitHub](https://github.com/jeffreyesdavid/tx-guard)")

scam_set = scams()
eth = chain()
st.caption(f"Checking against {len(scam_set):,} known scam addresses (ScamSniffer)."
           + ("" if eth else " On-chain checks are off in this demo."))

tx_tab, addr_tab = st.tabs(["Check a transaction", "Check an address"])

with tx_tab:
    pick = st.selectbox("Try an example", ["(enter your own)"] + list(EXAMPLES))
    to0, data0 = EXAMPLES.get(pick, ("", ""))
    to = st.text_input("To (contract or recipient)", value=to0, placeholder="0x…")
    data = st.text_area("Data (calldata from your wallet)", value=data0, placeholder="0x…", height=100)
    eth_value = st.number_input("ETH value", min_value=0.0, value=0.0, format="%.6f")
    if st.button("Check transaction", type="primary"):
        try:
            report(check_transaction(to.strip(), data.strip() or "0x", int(eth_value * 1e18), scam_set, eth))
        except (ValueError, RuntimeError) as e:
            st.error(f"Couldn't check that: {e}")

with addr_tab:
    sample = next(iter(sorted(scam_set)), "")
    addr = st.text_input("Address", placeholder="0x…", help=f"Try a known scam address: {sample}")
    if st.button("Check address", type="primary"):
        try:
            report(check_address(addr.strip(), scam_set, eth))
        except (ValueError, RuntimeError) as e:
            st.error(f"Couldn't check that: {e}")

st.divider()
st.caption("Educational tool. A clean result doesn't guarantee safety. Never paste your seed phrase or private key anywhere.")
