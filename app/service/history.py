from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock


@dataclass(slots=True)
class HistoryItem:
    scan_id: str
    created_at: str
    payload: dict[str, object]

    def summary(self) -> dict[str, object]:
        request = self.payload.get("request", {})
        report = self.payload.get("scan_report", {})
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        scores = report.get("scores", {}) if isinstance(report, dict) else {}
        return {
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "input_mode": request.get("input_mode"),
            "source_hint": request.get("source_hint"),
            "output_language": report.get("output_language"),
            "decision": report.get("decision"),
            "finding_count": summary.get("finding_count", 0),
            "overall": scores.get("overall"),
        }


class ScanHistory:
    def __init__(self, max_entries: int = 50):
        self.max_entries = max_entries
        self._items: OrderedDict[str, HistoryItem] = OrderedDict()
        self._counter = 0
        self._lock = Lock()

    def add(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            self._counter += 1
            scan_id = f"scan-{self._counter:05d}"
            item = HistoryItem(
                scan_id=scan_id,
                created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                payload=deepcopy(payload),
            )
            self._items[scan_id] = item
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
            return item.summary()

    def list_items(self) -> list[dict[str, object]]:
        with self._lock:
            return [item.summary() for item in reversed(self._items.values())]

    def get_payload(self, scan_id: str) -> dict[str, object] | None:
        with self._lock:
            item = self._items.get(scan_id)
            if item is None:
                return None
            return deepcopy(item.payload)
