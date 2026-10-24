"""Small helpers that clean the text ScamShield receives before analysis."""


def strip_agent_mention(text: str, address: str) -> str:
    """Remove a leading '@<this agent's own address>' mention, if present.

    ASI:One chat has been observed to put this mention in front of the user's
    message. Only this agent's OWN address is removed, and only at the very
    start, so nothing the user wrote is ever altered or hidden.
    """
    stripped = text.lstrip()
    mention = "@" + address
    if stripped.startswith(mention):
        return stripped[len(mention):].lstrip()
    return text