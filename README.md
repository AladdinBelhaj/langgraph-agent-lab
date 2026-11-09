# LangGraph Agent Lab

Container security triage for Trivy scan findings and Falco runtime events.

## Project layout

- `triage_agent/` — API, graph, schemas, and triage logic
- `scripts/` — command-line utilities and LLM-driven evaluation/demo scripts
- `fixtures/` — sample Trivy and Falco input data
- `logs/` — archived build logs

## Run the API

Set `LLM_MODEL`, `LLM_BASE_URL`, and `LLM_API_KEY`, then start the server:

```powershell
uvicorn triage_agent.api:app --reload
```

The API exposes `GET /health` and `POST /triage/trivy`; interactive API
documentation is available at `/docs`.

## Run utilities

From the project root:

```powershell
python -m scripts.triage_trivy fixtures/trivy/sample_nginx.json
python -m scripts.visualize_graph
python -m scripts.evaluate_falco
python -m scripts.evaluate_trivy
```
