"""Builds the plain-text reply that ScamShield sends back to ASI:One.

Version 1 (preliminary): it only reports warning signs found in the message
text. It does not assign a risk category yet and it never says a message is safe.
"""

from analysis import AnalysisResult, analyze

MAX_LISTED = 15


def build_report(result: AnalysisResult) -> str:
    lines = [
        "ScamShield report (preliminary: message-text check only)",
        "",
        "Risk category: not assessed yet (risk rules are not built in this version).",
        "",
    ]

    if result.flags:
        total = len(result.flags)
        lines.append(f"Warning signs found in the message text ({total}):")
        for i, flag in enumerate(result.flags[:MAX_LISTED], start=1):
            lines.append(f'{i}. "{flag.quote}" - {flag.label}')
        if total > MAX_LISTED:
            lines.append(f"...and {total - MAX_LISTED} more not shown.")
        lines.append("")
        lines.append(
            "These are warning signs, not proof. Legitimate messages can "
            "contain some of them too."
        )
    else:
        lines.append(
            "No warning signs matched my English wording rules. "
            "This does NOT mean the message is safe."
        )

    if result.truncated:
        lines.append("")
        lines.append("Note: the message was very long, so only the first part was checked.")

    lines += [
        "",
        "What this check did NOT do:",
        "- It did not check any link against threat-intelligence sources.",
        "- It did not verify the sender, phone number, company or offer.",
        "- It only knows some English wording patterns. Scams can use other words or languages.",
        "",
        "Never share an OTP, PIN, CVV or password with anyone. If money was already "
        "lost to online fraud in India, the official channels are helpline 1930 and "
        "cybercrime.gov.in.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sample = (
        "URGENT: Your SBI account will be blocked today. Share your OTP "
        "immediately. Click http://bit.ly/abc123"
    )
    print(build_report(analyze(sample)))
    print("\n" + "=" * 40 + "\n")
    print(build_report(analyze("Hi, are we meeting at 5 pm tomorrow?")))