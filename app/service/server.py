from __future__ import annotations

import argparse
import cgi
import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from skill_safe import __version__
from skill_safe.ingest import IngestError

from app.service.scan_service import UploadedFile, scan_archive_upload, scan_directory_upload, scan_path, scan_url

APP_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = APP_ROOT / "ui"


class SkillSafeAppHandler(BaseHTTPRequestHandler):
    server_version = f"SkillSafeApp/{__version__}"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "service": "skill-safe-web", "version": __version__})
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/v1/scan/path":
                payload = self._read_json_body()
                response = scan_path(
                    str(payload["path"]),
                    lang=self._parse_lang(payload.get("lang", "auto")),
                    dynamic=self._parse_bool(payload.get("dynamic", False)),
                )
                self._send_json(HTTPStatus.OK, response)
                return
            if parsed.path == "/api/v1/scan/url":
                payload = self._read_json_body()
                response = scan_url(
                    str(payload["url"]),
                    lang=self._parse_lang(payload.get("lang", "auto")),
                    dynamic=self._parse_bool(payload.get("dynamic", False)),
                )
                self._send_json(HTTPStatus.OK, response)
                return
            if parsed.path == "/api/v1/scan/upload":
                response = self._handle_upload_scan()
                self._send_json(HTTPStatus.OK, response)
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": f"Unknown endpoint: {parsed.path}"}})
        except Exception as exc:  # noqa: BLE001
            self._handle_api_error(exc)

    def _serve_static(self, request_path: str) -> None:
        relative = request_path.strip("/") or "index.html"
        if relative.startswith("api/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": f"Unknown endpoint: /{relative}"}})
            return
        candidate = (UI_ROOT / relative).resolve()
        ui_root = UI_ROOT.resolve()
        if not str(candidate).startswith(str(ui_root)) or not candidate.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": "Static asset not found"}})
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        payload = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        header_value = content_type
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            header_value = f"{content_type}; charset=utf-8"
        self.send_header("Content-Type", header_value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object.")
        return payload

    def _handle_upload_scan(self) -> dict[str, object]:
        form = self._read_form_data()
        lang = self._parse_lang(self._get_form_value(form, "lang", "auto"))
        dynamic = self._parse_bool(self._get_form_value(form, "dynamic", "false"))
        input_mode = self._get_form_value(form, "input_mode", "archive")
        if input_mode == "archive":
            if "archive" not in form:
                raise ValueError("Archive upload is missing.")
            item = form["archive"]
            if isinstance(item, list):
                item = item[0]
            if not getattr(item, "filename", None):
                raise ValueError("Archive upload is missing.")
            uploaded = UploadedFile(filename=str(item.filename), content=item.file.read())
            return scan_archive_upload(uploaded, lang=lang, dynamic=dynamic)
        if input_mode == "directory":
            if "files" not in form:
                raise ValueError("Directory upload is missing.")
            items = form["files"]
            if not isinstance(items, list):
                items = [items]
            uploads = [
                UploadedFile(filename=str(item.filename), relative_path=str(item.filename), content=item.file.read())
                for item in items
                if getattr(item, "filename", None)
            ]
            return scan_directory_upload(uploads, lang=lang, dynamic=dynamic)
        raise ValueError("input_mode must be 'archive' or 'directory'.")

    def _read_form_data(self) -> cgi.FieldStorage:
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
        }
        return cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=environ, keep_blank_values=True)

    def _parse_lang(self, value: object) -> str:
        lang = str(value)
        if lang not in {"auto", "zh", "en"}:
            raise ValueError("lang must be one of: auto, zh, en")
        return lang

    def _parse_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        return normalized in {"1", "true", "yes", "on"}

    def _get_form_value(self, form: cgi.FieldStorage, key: str, default: str) -> str:
        if key not in form:
            return default
        value = form[key]
        if isinstance(value, list):
            value = value[0]
        return value.value if hasattr(value, "value") else default

    def _handle_api_error(self, exc: Exception) -> None:
        if isinstance(exc, (ValueError, IngestError)):
            status = HTTPStatus.BAD_REQUEST
        elif isinstance(exc, FileNotFoundError):
            status = HTTPStatus.NOT_FOUND
        else:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        self._send_json(
            status,
            {
                "error": {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                }
            },
        )

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), SkillSafeAppHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skill-safe-web", description="Run the skill-safe web UI and REST API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = build_server(args.host, args.port)
    print(f"skill-safe web app listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        print("\nshutting down...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
