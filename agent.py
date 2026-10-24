import os
from datetime import datetime, timezone
from uuid import uuid4

from dotenv import load_dotenv
from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    TextContent,
    chat_protocol_spec,
)

from analysis import analyze
from inputclean import strip_agent_mention
from report import build_report

load_dotenv()

SEED = os.getenv("SCAMSHIELD_SEED")
if not SEED:
    raise SystemExit("SCAMSHIELD_SEED is missing. Add it to your .env file.")

# Debug switch, OFF by default. Only set SCAMSHIELD_DEBUG_TEXT=1 while testing
# with harmless messages. It prints the raw text the agent received.
DEBUG_TEXT = os.getenv("SCAMSHIELD_DEBUG_TEXT") == "1"

agent = Agent(
    name="ScamShield",
    seed=SEED,
    port=8001,
    mailbox=True,
    publish_agent_details=True,
)

protocol = Protocol(spec=chat_protocol_spec)

EMPTY_REPLY = (
    "Please paste the suspicious SMS, WhatsApp message, email, job offer or "
    "link you want me to look at. Never send me an OTP, PIN or password."
)


@protocol.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    # Acknowledge receipt first, as the Agent Chat Protocol example does.
    await ctx.send(
        sender,
        ChatAcknowledgement(
            timestamp=datetime.now(timezone.utc),
            acknowledged_msg_id=msg.msg_id,
        ),
    )

    # Collect the text. The message is untrusted data: it is only matched
    # against patterns, never executed, never followed as instructions,
    # never stored, and its content is never written to the logs
    # (except when the debug switch above is deliberately turned on).
    raw_text = ""
    for item in msg.content:
        if isinstance(item, TextContent):
            raw_text += item.text

    if DEBUG_TEXT:
        ctx.logger.warning(f"DEBUG raw text received: {raw_text!r}")

    # ASI:One puts "@<this agent's address>" in front of the user's message.
    # Remove only that mention so the rules see just what the user sent.
    text = strip_agent_mention(raw_text, agent.address)

    if text.strip():
        result = analyze(text)
        reply = build_report(result)
        ctx.logger.info(
            f"Analysed a message of {len(text)} characters: "
            f"{len(result.flags)} warning signs."
        )
    else:
        reply = EMPTY_REPLY
        ctx.logger.info("Received a message with no text.")

    await ctx.send(
        sender,
        ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(type="text", text=reply),
                EndSessionContent(type="end-session"),
            ],
        ),
    )


@protocol.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    pass


agent.include(protocol, publish_manifest=True)

if __name__ == "__main__":
    agent.run()