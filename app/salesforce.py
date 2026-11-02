from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

from app.common import clock


def collect(instance: str, token: str) -> dict[str, Any]:
    if not re.fullmatch(
        r"https://[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:my\.salesforce\.com|salesforce\.com)",
        instance,
    ):
        raise ValueError("An explicit HTTPS Salesforce instance is required")

    def read(client: httpx.Client, endpoint: str) -> Any:
        if (
            not endpoint.startswith("/services/data/")
            or ".." in endpoint
            or "\\" in endpoint
            or "#" in endpoint
        ):
            raise ValueError("Native pagination path rejected")
        with client.stream("GET", instance + endpoint) as response:
            if response.status_code != 200:
                raise ValueError("Native read rejected; no clean assessment produced")
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 262144:
                    raise ValueError("Native response exceeds 256 KiB")
        return json.loads(data)

    with httpx.Client(
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
        trust_env=False,
        timeout=10,
    ) as client:
        versions = read(client, "/services/data/")
        if not isinstance(versions, list) or not versions:
            raise ValueError("Native version discovery failed")
        version = max(
            (
                str(v["version"])
                for v in versions
                if re.fullmatch(r"[0-9]{2,3}\.0", str(v.get("version", "")))
            ),
            key=lambda v: int(v.split(".")[0]),
        )
        query = "SELECT Id,Name,PermissionsModifyAllData FROM PermissionSet"
        endpoint = f"/services/data/v{version}/query?" + str(httpx.QueryParams({"q": query}))
        records: list[dict[str, Any]] = []
        for _ in range(5):
            page = read(client, endpoint)
            if not isinstance(page, dict) or not isinstance(page.get("records"), list):
                raise ValueError("Invalid native query response")
            for record in page["records"]:
                if (
                    not isinstance(record, dict)
                    or not isinstance(record.get("Id"), str)
                    or not isinstance(record.get("Name"), str)
                    or type(record.get("PermissionsModifyAllData")) is not bool
                ):
                    raise ValueError("Invalid native permission-set record")
                records.append(
                    {key: record[key] for key in ["Id", "Name", "PermissionsModifyAllData"]}
                )
            if len(records) > 1000:
                raise ValueError("Native record cap reached; assessment incomplete")
            if page.get("done") is True:
                break
            endpoint = page.get("nextRecordsUrl", "")
            if not isinstance(endpoint, str) or not endpoint.startswith(
                f"/services/data/v{version}/query/"
            ):
                raise ValueError("Native pagination path rejected")
        else:
            raise ValueError("Native page cap reached; assessment incomplete")
    raw_sha = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "format": "salesforce-permission-set-observations-v1",
        "observed_at": clock(),
        "source": instance,
        "records": records,
        "source_sha256": raw_sha,
        "scope": "permission_set_definitions_only_assignments_muting_connected_apps_and_effective_access_not_evaluated",
        "mfa_and_oauth_scopes": "not_collected",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    file = args.credential_file
    if file.is_symlink() or file.stat().st_mode & 0o077:
        raise ValueError("Credential file must be private")
    credential = json.loads(file.read_text())
    if (
        set(credential) != {"access_token"}
        or not isinstance(credential["access_token"], str)
        or len(credential["access_token"]) < 20
    ):
        raise ValueError("Invalid private credential file")
    result = collect(args.instance, credential["access_token"])
    with os.fdopen(
        os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w"
    ) as output:
        json.dump(result, output, indent=2)
    print(
        json.dumps(
            {
                "output_written": True,
                "records": len(result["records"]),
                "effective_access": "not_evaluated",
            }
        )
    )


if __name__ == "__main__":
    main()
