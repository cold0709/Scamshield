from importlib.metadata import version

print("uagents version:", version("uagents"))

from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import(
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    TextContent,
    chat_protocol_spec,
)

print("Imports OK: uagents and agent chat protocol are available.")