from __future__ import annotations

import uvicorn

from traust_ledger.service.app import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="0.0.0.0", port=8000)
