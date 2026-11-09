from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from falco_core import triage_event
from schema import RuntimeTriage, Triage
from triage_core import triage


class State(TypedDict):
    payload: dict
    result: Triage | RuntimeTriage


def route(state: State):
    return "falco_agent" if "output_fields" in state["payload"] else "trivy_agent"


def trivy_agent(state: State):
    return {"result": triage(state["payload"]["text"])}


def falco_agent(state: State):
    return {"result": triage_event(state["payload"])}


g = StateGraph(State)
g.add_node("trivy_agent", trivy_agent)
g.add_node("falco_agent", falco_agent)
g.add_conditional_edges(START, route)
g.add_edge("trivy_agent", END)
g.add_edge("falco_agent", END)
app = g.compile()


def run(payload: dict):
    return app.invoke({"payload": payload})["result"]