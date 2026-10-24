# ScamShield

An agent for the ASI:One Agent Challenge (Fetch-A-Thon 3.0). You paste a
suspicious SMS, WhatsApp message, email, job offer or link into an ASI:One
conversation, and ScamShield reports the warning signs it finds, quoted
exactly from your message.

**Status: work in progress.**

## What works now
- A uAgent that speaks the Agent Chat Protocol, connected to Agentverse through a mailbox and reachable from ASI:One chat.
- Rule-based detection of English warning signs (urgency, OTP/password requests, upfront fees, account threats, fake prizes, too-good offers, informal channels, shortened links).
- Honest reporting: it never says a message is safe, and it lists what it did not check.

## Not built yet
- Risk categories, URL threat-intelligence checks, Hindi and Hinglish rules, multi-agent orchestration.

## Agentverse Agent Profile
https://agentverse.ai/agents/details/agent1qw0lf4msch5d7ugm96gdxuf073gthyx9n45u8t62avkqv3mr9pxkk9y9l0l/profile

## Run it yourself (Windows PowerShell)
Requires Python 3.10 to 3.13 and an Agentverse account.

```
git clone <this repository's URL>
cd scamshield
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the printed value after `SCAMSHIELD_SEED=` in `.env`, then:

```
python agent.py
```

1. Open the "Agent inspector" link printed in the terminal and log in to Agentverse.
2. Click **Connect**, choose **Mailbox**, and follow the prompts.
3. Open the Agent Profile, click **Chat with Agent**, and paste a message.

Keep `agent.py` running while you chat.

## Run the tests
```
python test_analysis.py
python test_inputclean.py
```

## Security
- Your seed lives only in `.env`, which is git-ignored. Never commit it.
- The submitted message is treated as untrusted text: it is only matched against patterns, never followed as instructions, never stored, and never written to logs.
- Links are never opened.