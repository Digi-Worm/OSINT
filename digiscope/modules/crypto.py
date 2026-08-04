"""Passive Bitcoin/ETH address context and explorer links."""

from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import quote

from ..models import Section
from .base import ScanContext, add_entity, add_failure, add_link, add_timeline, new_result, register

BTC_RE = re.compile(r"^(?:bc1[a-z0-9]{20,87}|[13][1-9A-HJ-NP-Za-km-z]{24,39})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


async def _bitcoin(ctx: ScanContext, address: str) -> Dict[str, Any]:
    url = f"https://blockchain.info/rawaddr/{quote(address, safe='')}"
    response = await ctx.fetcher.get_json(url, params={"limit": 5}, source="Blockchain.com", max_bytes=1_000_000)
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    payload = response.data
    txs = []
    for tx in payload.get("txs", [])[:5] if isinstance(payload.get("txs"), list) else []:
        if isinstance(tx, dict):
            txs.append({"hash": tx.get("hash", ""), "time": tx.get("time", ""), "size": tx.get("size", ""), "inputs": len(tx.get("inputs", []) or []), "outputs": len(tx.get("out", []) or [])})
    return {
        "ok": True,
        "url": url,
        "address": payload.get("address", address),
        "final_balance_btc": (payload.get("final_balance", 0) or 0) / 100_000_000,
        "total_received_btc": (payload.get("total_received", 0) or 0) / 100_000_000,
        "total_sent_btc": (payload.get("total_sent", 0) or 0) / 100_000_000,
        "transaction_count": payload.get("n_tx", 0),
        "transactions": txs,
    }


async def _ethereum(ctx: ScanContext, address: str) -> Dict[str, Any]:
    url = f"https://api.blockchair.com/ethereum/dashboards/address/{quote(address, safe='')}"
    response = await ctx.fetcher.get_json(url, params={"transaction_details": "true"}, source="Blockchair Ethereum", max_bytes=1_000_000)
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    data = (response.data.get("data") or {}).get(address.lower()) or (response.data.get("data") or {}).get(address) or {}
    address_data = data.get("address", {}) if isinstance(data, dict) else {}
    return {"ok": True, "url": url, "address": address, "balance_wei": address_data.get("balance", ""), "transaction_count": address_data.get("transaction_count", ""), "calls": address_data.get("calls", "")}


@register(
    "crypto",
    "Crypto address context",
    "Passive Bitcoin balance/transaction context, optional keyless Ethereum dashboard and explorer pivots.",
    category="financial",
    sources=["Blockchain.com", "Blockchair", "block explorers"],
)
async def run_crypto(ctx: ScanContext, target: str) -> Any:
    address = target.strip()
    is_eth = bool(ETH_RE.fullmatch(address))
    is_btc = bool(BTC_RE.fullmatch(address))
    result = new_result("crypto", address)
    if not is_eth and not is_btc:
        result.status = "error"
        result.error = "Address is not a recognised Bitcoin or Ethereum shape"
        return result
    kind = "Ethereum" if is_eth else "Bitcoin"
    result.sections.append(Section("Address identification", "kv", {"address": address, "network": kind, "validation": "shape check only"}, "An address does not identify its controller."))
    add_entity(result, "crypto", address, "crypto.input", pivot=False, label=f"{kind} address")

    lookup = await _ethereum(ctx, address) if is_eth else await _bitcoin(ctx, address)
    if lookup.get("ok"):
        rows = {key: value for key, value in lookup.items() if key not in {"ok", "url", "transactions"}}
        result.sections.append(Section(f"{kind} public context", "kv", rows, "Public chain indexer response; values may lag the chain.", lookup.get("url", "")))
        if lookup.get("transactions"):
            result.sections.append(Section("Recent transactions", "table", lookup["transactions"], "At most five recent records returned."))
            for transaction in lookup["transactions"]:
                if transaction.get("time"):
                    add_timeline(result, transaction["time"], "Bitcoin transaction observed", "Blockchain.com", transaction.get("hash", ""))
    else:
        add_failure(result, "Blockchain indexer", lookup.get("error", "unavailable"))

    encoded = quote(address, safe="")
    if is_btc:
        add_link(result, "Blockchain.com explorer", f"https://www.blockchain.com/explorer/addresses/btc/{encoded}", "explorer", "Blockchain.com")
        add_link(result, "Blockchair Bitcoin explorer", f"https://blockchair.com/bitcoin/address/{encoded}", "explorer", "Blockchair")
    else:
        add_link(result, "Etherscan explorer", f"https://etherscan.io/address/{encoded}", "explorer", "Etherscan")
        add_link(result, "Blockchair Ethereum explorer", f"https://blockchair.com/ethereum/address/{encoded}", "explorer", "Blockchair")
    exact_query = quote('"' + address + '"', safe="")
    add_link(result, "Google exact-address search", "https://www.google.com/search?q=" + exact_query, "search", "Google")
    result.coverage.update({"network": kind, "indexer": lookup.get("ok", False)})
    return result


__all__ = ["run_crypto"]
