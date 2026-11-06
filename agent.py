import os
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph import StateGraph, MessagesState, START
from langgraph.prebuilt import ToolNode, tools_condition


@tool
def read_log(path: str) -> str:
    """Return the last 50 lines of a log file."""
    with open(path, encoding="utf-8") as f:
        return "".join(f.readlines()[-50:])


@tool
def count_matches(path: str, word: str) -> int:
    """Count lines in a file that contain the given word (case-insensitive)."""
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if word.lower() in line.lower())


tools = [read_log, count_matches]

llm = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
).bind_tools(tools)


def call_model(state: MessagesState):
    return {"messages": [llm.invoke(state["messages"])]}


graph = StateGraph(MessagesState)
graph.add_node("model", call_model)
graph.add_node("tools", ToolNode(tools))
graph.add_edge(START, "model")
graph.add_conditional_edges("model", tools_condition)  # tool call -> "tools", else END
graph.add_edge("tools", "model")                       # tool result goes back to the model
app = graph.compile()

if __name__ == "__main__":
    question = "Look at build.log. Why did the build fail? How many ERROR lines are there?"
    for step in app.stream({"messages": [("user", question)]}, stream_mode="values"):
        step["messages"][-1].pretty_print()