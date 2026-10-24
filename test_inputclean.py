import sys

from inputclean import strip_agent_mention

ADDR = "agent1qtestaddress"
failures = 0


def check(name, got, expected):
    global failures
    ok = got == expected
    print(("PASS" if ok else "FAIL"), "-", name)
    if not ok:
        print("      got:     ", repr(got))
        print("      expected:", repr(expected))
        failures += 1


check("1. Own mention is removed",
      strip_agent_mention(f"@{ADDR} hello", ADDR), "hello")
check("2. Plain message is unchanged",
      strip_agent_mention("hello", ADDR), "hello")
check("3. Someone else's mention is kept",
      strip_agent_mention("@agent1qother hello", ADDR), "@agent1qother hello")
check("4. Mention only gives empty text",
      strip_agent_mention(f"@{ADDR}", ADDR), "")
check("5. Own address in the middle is kept",
      strip_agent_mention(f"hello @{ADDR} there", ADDR), f"hello @{ADDR} there")
check("6. Multi-line message keeps its lines",
      strip_agent_mention(f"@{ADDR} line one\nline two", ADDR), "line one\nline two")

print()
if failures:
    print(f"{failures} test(s) FAILED")
    sys.exit(1)
print("All tests passed")