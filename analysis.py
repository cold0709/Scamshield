"""ScamShield message analysis: rule-based warning-sign finder (English only for now).

This module is plain Python. It never calls the network, never opens URLs,
and never interprets the message as instructions, so a message such as
"ignore previous instructions" has no effect on it. Every flag carries an
exact quote copied from the original message.

Flags are WARNING SIGNS, not verdicts. Many of them also appear in
legitimate messages.
"""

import re
from dataclasses import dataclass

MAX_CHARS = 5000  # analyse at most this many characters of any message


@dataclass(frozen=True)
class Flag:
    rule_id: str
    label: str
    quote: str  # exact substring of the original message
    start: int  # position of the quote in the analysed text


@dataclass(frozen=True)
class AnalysisResult:
    flags: list
    truncated: bool  # True if the message was longer than MAX_CHARS


@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    pattern: re.Pattern
    skip_if_negated: bool = False


def _rx(*alternatives: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{a})" for a in alternatives), re.IGNORECASE)


RULES = [
    Rule(
        "CREDENTIAL_REQUEST",
        "Asks you to share or enter an OTP, PIN, CVV or password",
        _rx(
            r"\b(?:share|send|tell|give|enter|provide|confirm|forward|submit)\b"
            r"[^.\n]{0,40}?\b(?:otp|one[- ]time password|pin|cvv|password|passcode)\b"
        ),
        skip_if_negated=True,
    ),
    Rule(
        "URGENCY",
        "Pressure or urgency wording",
        _rx(
            r"\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b",
            r"\blast\s+chance\b",
            r"\bact\s+now\b",
            r"\bexpires?\s+(?:today|soon|tonight)\b",
            r"\bfinal\s+(?:notice|warning)\b",
        ),
    ),
    Rule(
        "ACCOUNT_THREAT",
        "Threatens that an account, card, SIM or KYC will be blocked or expire",
        _rx(
            r"\b(?:account|sim|card|kyc|aadhaar|pan|upi)\b[^.\n]{0,40}?"
            r"\b(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:ed|e)|expire[sd]?|"
            r"freez(?:e|ing)|frozen|clos(?:e|ed)|terminat(?:ed|e))\b",
            r"\bupdate\s+(?:your\s+)?kyc\b",
        ),
    ),
    Rule(
        "UPFRONT_FEE",
        "Asks for a fee or deposit up front",
        _rx(
            r"\b(?:registration|processing|security|refundable|joining|training|kit|verification)"
            r"\s+(?:fee|deposit|charges?)\b",
            r"\bpay\b[^.\n]{0,40}?\b(?:fee|deposit|charges?)\b",
        ),
    ),
    Rule(
        "PRIZE_OR_SELECTION",
        "Unexpected prize, win or 'you were selected' claim",
        _rx(
            r"\byou(?:\s+have)?\s+won\b",
            r"\blottery\b",
            r"\blucky\s+draw\b",
            r"\bprize\b",
            r"\bcongratulations\b[^.\n]{0,60}?\b(?:selected|won|winner)\b",
        ),
    ),
    Rule(
        "TOO_GOOD_OFFER",
        "Offer that sounds too good: high pay, no interview, guaranteed income",
        _rx(
            r"\bearn\s+(?:rs\.?|₹|inr)?\s*\d[\d,]*\s*(?:/|per|a)\s*(?:day|daily|hour|week)\b",
            r"\bno\s+interview\b",
            r"\bwithout\s+(?:any\s+)?interview\b",
            r"\bno\s+experience\s+(?:needed|required)\b",
            r"\bguaranteed\s+(?:job|income|returns?|profit)\b",
        ),
    ),
    Rule(
        "UNOFFICIAL_CHANNEL",
        "Uses an informal channel (WhatsApp, Telegram or a free email address)",
        _rx(
            r"\b(?:whatsapp|telegram)\b",
            r"[\w.+-]+@(?:gmail|yahoo|outlook|hotmail|rediffmail)\.com",
        ),
    ),
    Rule(
        "SHORTENED_URL",
        "Contains a shortened link that hides the real destination",
        _rx(
            r"(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)/[^\s<>\"']+",
        ),
    ),
]

# Words just before a match that turn a request into a warning
# (e.g. "Do not share your OTP").
_NEGATION = re.compile(
    r"(?:do\s+not|don't|dont|never|not)\s+(?:\w+\s+){0,2}$", re.IGNORECASE
)


def _is_negated(text: str, start: int) -> bool:
    window = text[max(0, start - 25):start]
    return bool(_NEGATION.search(window))


def analyze(text: str) -> AnalysisResult:
    truncated = len(text) > MAX_CHARS
    body = text[:MAX_CHARS]
    flags = []
    for rule in RULES:
        for m in rule.pattern.finditer(body):
            if rule.skip_if_negated and _is_negated(body, m.start()):
                continue
            flags.append(Flag(rule.rule_id, rule.label, m.group(0), m.start()))
    flags.sort(key=lambda f: f.start)
    return AnalysisResult(flags=flags, truncated=truncated)


def quotes_are_exact(text: str, result: AnalysisResult) -> bool:
    """True if every quoted warning sign is an exact piece of the message."""
    return all(
        text[f.start:f.start + len(f.quote)] == f.quote for f in result.flags
    )