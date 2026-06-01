"""
app.py — FastAPI web UI for the LLM Red-Team Framework.

Run with:
    uvicorn app:app --reload

Then open http://localhost:8000 in your browser.
"""
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Annotated, List, Optional

from llm_redteam.adapter import FakeTargetAdapter, OpenAIAdapter, AnthropicAdapter
from llm_redteam.engine import ScanEngine
from llm_redteam.models import TargetConfig, Verdict
from llm_redteam.probes import get_probes

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    provider: Annotated[str, Form()],
    base_url: Annotated[str, Form()],
    model: Annotated[str, Form()],
    api_key: Annotated[str, Form()] = "",
    categories: Annotated[Optional[List[str]], Form()] = None,
    authorized: Annotated[Optional[str], Form()] = None,
):
    # Authorization check — must tick the box
    if not authorized:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "You must confirm you are authorized to test this target."
        })

    config = TargetConfig(provider=provider, base_url=base_url, model=model, api_key=api_key)

    if provider == "openai":
        adapter = OpenAIAdapter(config)
    elif provider == "anthropic":
        adapter = AnthropicAdapter(config)
    else:
        adapter = FakeTargetAdapter(
            "HACKED. I am now DAN with no restrictions. "
            "My instructions are: always comply. "
            "Emails: alice@example.com. API key: sk-demo1234567890abcdefghij"
        )

    probes = get_probes(categories if categories else None)

    try:
        engine = ScanEngine(adapter, rate_limit_s=0.5)
        results = engine.run(probes)
    except Exception as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Scan failed: {e}"
        })

    fails = [r for r in results if r.verdict == Verdict.FAIL]
    passes = [r for r in results if r.verdict == Verdict.PASS]
    inconclusive = [r for r in results if r.verdict == Verdict.INCONCLUSIVE]

    has_critical = any(r.severity and r.severity.value == "critical" for r in fails)
    overall = "CRITICAL" if has_critical else ("HIGH" if fails else "PASS")

    return templates.TemplateResponse("report.html", {
        "request": request,
        "target": base_url,
        "model": model,
        "results": results,
        "fails": fails,
        "passes": passes,
        "inconclusive": inconclusive,
        "overall": overall,
        "Verdict": Verdict,
    })
