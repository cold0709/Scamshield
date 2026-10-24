"""ScamShield message analysis: rule-based warning-sign finder.

Languages: English, Hindi (Devanagari), Hinglish (Hindi in Roman letters) and
mixed text.  Plain `re` only.  The message is untrusted data: it is matched
against patterns and never interpreted, stored or logged.
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
    negation: str = "en"  # "en": negator just before the match; "hi": Hindi/Hinglish aware


# --------------------------------------------------------------------------
# Pattern helpers
# --------------------------------------------------------------------------
# Devanagari block WITHOUT the danda (U+0964) and double danda (U+0965):
# those are punctuation and must act as word boundaries.
_D = r"\u0900-\u0963\u0966-\u097F"
_BL = rf"(?<![\w{_D}])"   # explicit "start of word"  (replaces \b)
_BR = rf"(?![\w{_D}])"    # explicit "end of word"    (replaces \b)

# Precomposed nukta letters (U+0958..U+095F) that some keyboards produce.
_PRECOMPOSED = {"क": "\u0958", "ख": "\u0959", "ग": "\u095a", "ज": "\u095b",
                "ड": "\u095c", "ढ": "\u095d", "फ": "\u095e", "य": "\u095f"}


def _indic(p: str) -> str:
    """Make a pattern tolerant of common Devanagari spelling variants.

    Shorthand used inside patterns:  ‹ = start of word,  › = end of word,
    ¶ = one Devanagari character (used with a quantifier, e.g. ¶{0,4}).
    Nukta is optional (ज = ज or ज़ in either encoding); ं and ँ are interchangeable.
    Write patterns WITHOUT nukta.  Never put these letters inside [...] classes.
    """
    p = p.replace("\u093c", "")
    out = []
    for ch in p:
        if ch in _PRECOMPOSED:
            out.append(f"(?:{ch}\u093c?|{_PRECOMPOSED[ch]})")
        elif ch in "ंँ":
            out.append("[ंँ]")
        elif ch == "‹":
            out.append(_BL)
        elif ch == "›":
            out.append(_BR)
        elif ch == "¶":
            out.append(f"[{_D}]")
        else:
            out.append(ch)
    return "".join(out)


def _rx(*alternatives: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{_indic(a)})" for a in alternatives), re.IGNORECASE)


def _gap(n: int) -> str:
    """Bounded, lazy gap that never crosses a sentence end (. । or newline)."""
    return rf"[^.।\n]{{0,{n}}}?"


# --------------------------------------------------------------------------
# Vocabulary shared by several rules
# --------------------------------------------------------------------------
_CRED = (r"(?:upi\s*pin|atm\s*pin|m-?pin|otp|one[- ]time\s+password|pin(?!\s*code)|cvv|cvc|"
         r"password|passwd|passcode|ओटीपी|ओ\s?टी\s?पी|वन[- ]टाइम\s+पासवर्ड|पिन(?!\s*कोड)|"
         r"सीवीवी|पासवर्ड|पासकोड|एमपिन)")
_CRED_VERB = (r"(?:share|send|forward|enter|submit|provide|confirm|read\s+out|type|"
              r"bhej\w{0,6}|bata\w{0,6}|batao|dijiye|dijiyega|dijie|dedo|dedijiye|dena|dein|den|denge|"
              r"daal\w{0,5}|dal(?:na|ein|en|iye)|bol\w{0,4}|maang\w{0,6}|mang\w{0,6}|likh\w{0,5}|"
              r"साझा|शेयर|बता¶{0,5}|भेज¶{0,5}|बोल¶{0,4}|दें|देना|देंगे|दीजिए|दीजिये|दीजिएगा|दीजियेगा|"
              r"डाल¶{0,5}|दर्ज|एंटर|मांग¶{0,5}|लिख¶{0,5}|पूछ¶{0,4}|रीड\s+आउट)")

_ENTITY = (r"(?:account|a/c|khata|khaata|sim|card|kyc|aadhaar|aadhar|pan|upi|wallet|netbanking|"
           r"net\s+banking|mobile\s+number|paytm|phonepe|"
           r"खाता|खाते|अकाउंट|एकाउंट|सिम|कार्ड|केवाईसी|के\s?वाई\s?सी|आधार|पैन|यूपीआई|वॉलेट|"
           r"मोबाइल\s+नंबर|नेट\s+बैंकिंग)")
_BLOCKED = (r"(?:block\w*|band|suspend\w*|deactivat\w*|expire\w*|freez\w*|frozen|lock\w*|inactive|"
            r"restrict\w*|terminat\w*|samapt|ब्लॉक¶{0,4}|बंद|निलंबित|सस्पेंड¶{0,4}|फ्रीज¶{0,4}|"
            r"एक्सपायर¶{0,4}|समाप्त|डिएक्टिवेट¶{0,4}|निष्क्रिय|प्रतिबंधित|लॉक¶{0,4})")

_AUTH = (r"(?:cbi|ncb|narcotics|crime\s+branch|police|cyber\s*(?:cell|crime)|customs|trai|income\s+tax|"
         r"court|thana|inspector|enforcement\s+directorate|"
         r"पुलिस|सीबीआई|नारकोटिक्स|क्राइम\s+ब्रांच|साइबर\s+(?:सेल|क्राइम)|कस्टम|ट्राई|आयकर|कोर्ट|"
         r"न्यायालय|थाना|इंस्पेक्टर|प्रवर्तन\s+निदेशालय)")
_ARREST = (r"(?:arrest\w*|giraftar\w*|giraftari|warrant|jail|money\s+laundering|"
           r"case\s+(?:darj|register|file)\w*|mukadma|fir\s+(?:darj|register|lodge|file)\w*|legal\s+action|"
           r"kanooni\s+karyavahi|kanuni\s+karyavahi|गिरफ्तार¶{0,5}|वारंट|वारण्ट|जेल|मनी\s+लॉन्ड्रिंग|"
           r"केस\s+दर्ज|मुकदमा|एफआईआर|कानूनी\s+कार्र?वाई)")
_TRADE = (r"(?:trading|stock|stocks|crypto|forex|share\s*market|investment|ipo|vip|"
          r"ट्रेडिंग|शेयर\s+बाजार|स्टॉक|निवेश|क्रिप्टो|फॉरेक्स|आईपीओ|वीआईपी)")

# --------------------------------------------------------------------------
# Rules.  Same rule_ids as before; Hindi/Hinglish alternatives added.
# --------------------------------------------------------------------------
RULES = [
    # --- credential request: English (negation sits BEFORE the verb) --------
    Rule("CREDENTIAL_REQUEST", "Asks you to share or enter an OTP, PIN, CVV or password",
        _rx(r"\b(?:share|send|tell|give|enter|provide|confirm|forward|submit)\b"
            r"[^.\n]{0,40}?\b(?:otp|one[- ]time password|pin|cvv|password|passcode)\b"),
        skip_if_negated=True),
    # --- credential request: Hinglish + Devanagari (negation AFTER the verb) -
    Rule("CREDENTIAL_REQUEST", "Asks you to share or enter an OTP, PIN, CVV or password",
        _rx("‹" + _CRED + "›" + _gap(40) + "‹" + _CRED_VERB + "›"),
        skip_if_negated=True, negation="hi"),

    Rule("URGENCY", "Pressure or urgency wording",
        _rx(r"\burgent(?:ly)?\b", r"\bimmediately\b",
            r"\bwithin\s+\d{1,6}\s*(?:hours?|hrs?|minutes?|mins?)\b", r"\blast\s+chance\b",
            r"\bact\s+now\b", r"\bexpires?\s+(?:today|soon|tonight)\b", r"\bfinal\s+(?:notice|warning)\b",
            # Hinglish
            r"‹(?:tur+a?n?t|tatkal|tatkaal|fauran|fauri)›",
            r"‹(?:jald\s*se\s*jald|jaldi\s+se\s+jaldi|jald\s+hi)›",
            r"‹(?:aakhri|akhri|antim)\s+(?:mauka|moka|chetavni|chetawani|suchna)›",
            r"‹\d{1,6}\s*(?:ghante|ghanto|ghanta|ghnte|minute|min)\s+(?:me|mein|mai|ke\s+andar|ke\s+bheetar)›",
            # Devanagari
            r"‹(?:तुरंत|तत्काल|फौरन|जल्द\s+से\s+जल्द)›",
            r"‹(?:आखिरी|अंतिम)\s+(?:मौका|चेतावनी|सूचना)›",
            r"‹\d{1,6}\s*(?:घंटे|घंटों|घण्टे|घंटा|मिनट)\s*(?:में|के\s+अंदर|के\s+भीतर)›")),

    Rule("ACCOUNT_THREAT", "Threatens that an account, card, SIM or KYC will be blocked or expire",
        _rx(r"\b(?:account|sim|card|kyc|aadhaar|pan|upi)\b[^.\n]{0,40}?"
            r"\b(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:ed|e)|expire[sd]?|"
            r"freez(?:e|ing)|frozen|clos(?:e|ed)|terminat(?:ed|e))\b",
            r"\bupdate\s+(?:your\s+)?kyc\b",
            # Hinglish / Devanagari / mixed: "account block ho jayega", "खाता बंद हो जाएगा"
            "‹" + _ENTITY + "›" + _gap(40) + "‹" + _BLOCKED + "›",
            r"‹kyc\s+(?:update|verification|verify)\s+(?:kar\w*|kij\w*|karwa\w*|nahi|pending)›",
            r"‹kyc\s+(?:pending|expired?|adhur[ae]|adhoor[ae]|incomplete)›",
            r"‹(?:update|verify)\s+(?:your\s+|apna\s+|aapka\s+)?kyc›",
            r"‹केवाईसी\s*(?:अपडेट|सत्यापन|वेरिफिकेशन)\s*(?:करें|करे|कीजिए|कीजिये|कराएं|करवाएं|नहीं)›",
            r"‹केवाईसी\s*(?:पेंडिंग|लंबित|अधूरा|एक्सपायर¶{0,3})›")),

    Rule("UPFRONT_FEE", "Asks for a fee or deposit up front",
        _rx(r"\b(?:registration|processing|security|refundable|joining|training|kit|verification)"
            r"\s+(?:fee|deposit|charges?)\b",
            r"\bpay\b[^.\n]{0,40}?\b(?:fee|deposit|charges?)\b",
            # Hinglish
            r"‹(?:registration|processing|security|refundable|joining|training|kit|verification|form)"
            r"\s+(?:fees?|shulk|deposit|charges?)›",
            r"‹(?:fees?|deposit|charges?|shulk)›" + _gap(40) +
            r"‹(?:jama\s+kar\w*|jama\s+kij\w*|bhej(?:iye|iyega|ein|en|o|na)|pay\s+kar\w*|"
            r"transfer\s+kar\w*|bhugtan\s+kar\w*)›",
            # Devanagari
            r"‹(?:रजिस्ट्रेशन|पंजीकरण|प्रोसेसिंग|सिक्योरिटी|जॉइनिंग|जोइनिंग|ट्रेनिंग|किट|वेरिफिकेशन|"
            r"सत्यापन|रिफंडेबल|फॉर्म|प्रवेश)\s*(?:शुल्क|फीस|राशि|चार्ज|डिपॉजिट|जमा)›",
            r"‹(?:शुल्क|फीस|चार्ज|राशि|डिपॉजिट)›" + _gap(40) +
            r"‹(?:जमा\s+कर¶{0,4}|भेज(?:ें|ना|िए|ो)|भुगतान\s+कर¶{0,4}|देना|दें)›")),

    Rule("PRIZE_OR_SELECTION", "Unexpected prize, win or 'you were selected' claim",
        _rx(r"\byou(?:\s+have)?\s+won\b", r"\blottery\b", r"\blucky\s+draw\b", r"\bprize\b",
            r"\bcongratulations\b[^.\n]{0,60}?\b(?:selected|won|winner)\b",
            # Hinglish
            r"‹(?:inaam|inam|puraskar|jackpot|kbc\s+lottery)›",
            r"‹(?:lucky|lottery|inaam|inam|prize|jackpot|winner|vijeta)›[^.\n]{0,50}?‹(?:chun\w*|select\w*)›",
            r"‹(?:chun\w*|select\w*)›[^.\n]{0,50}?‹(?:lucky|lottery|inaam|inam|prize|jackpot|winner|vijeta)›",
            r"‹(?:badhai|badhaai|mubarak)(?:\s+ho)?›[^.\n]{0,60}?‹(?:jeet\w*|jit\w*|winner|vijeta|inaam|lottery|prize)›",
            r"(?:‹(?:lakh|crore)›|₹\s*\d|‹rs\.?\s*\d)[^.\n]{0,30}?‹(?:jeet|jit|jeeti|jeete|jita)\w*›",
            # Devanagari
            r"‹(?:लॉटरी|लाटरी|इनाम|ईनाम|पुरस्कार|जैकपॉट|लकी\s+ड्रॉ|केबीसी\s+लॉटरी)›",
            r"‹(?:लकी|लॉटरी|इनाम|ईनाम|पुरस्कार|जैकपॉट|विजेता)›" + _gap(50) + r"‹(?:चुन¶{0,5}|चयन¶{0,5}|सेलेक्ट¶{0,5})",
            r"‹बधाई›" + _gap(60) + r"‹(?:जीत¶{0,5}|विजेता|इनाम|ईनाम|लॉटरी)",
            r"(?:‹(?:लाख|करोड)›|₹\s*\d)" + _gap(30) + r"‹जीत¶{0,5}")),

    Rule("TOO_GOOD_OFFER", "Offer that sounds too good: high pay, no interview, guaranteed income",
        _rx(r"\bearn\s+(?:rs\.?|₹|inr)?\s*\d[\d,]{0,12}\s*(?:/|per|a)\s*(?:day|daily|hour|week)\b",
            r"\bno\s+interview\b", r"\bwithout\s+(?:any\s+)?interview\b",
            r"\bno\s+experience\s+(?:needed|required)\b",
            r"\bguaranteed\s+(?:job|income|returns?|profit)\b",
            # Hinglish
            r"‹(?:rs\.?|₹|inr)?\s*\d[\d,]{0,12}\s*(?:/-|/\s*day)?\s*(?:rozana|roz|daily|har\s+din|prati\s*din|per\s+day)\s*(?:tak\s+)?kama\w{0,6}›",
            r"‹(?:rozana|roz|daily|har\s+din|prati\s*din)\s+(?:rs\.?|₹|inr)?\s*\d[\d,]{0,12}\s*(?:/-)?\s*(?:tak\s+)?kama\w{0,6}›",
            r"‹ghar\s+baithe›[^.\n]{0,30}?‹(?:kama\w*|income|paise|earn\w*)›",
            r"‹(?:bina|bina\s+kisi)\s+(?:interview|experience)›",
            r"‹interview\s+(?:ke\s+bina|nahi|nhi)›",
            r"‹(?:koi\s+)?experience\s+(?:ki\s+zarurat|ki\s+jarurat)\s+nahi›",
            r"‹(?:pakka|pakki)\s+(?:job|naukri|income|munafa|profit|returns?|kamai)›",
            r"‹guarantee(?:d)?\s+(?:job|naukri|income|munafa|profit|returns?)›",
            # Devanagari
            r"‹घर\s+बैठे›" + _gap(30) + r"‹(?:कमा¶{0,6}|कमाई|आमदनी|पैसे)›",
            r"‹बिना\s+(?:किसी\s+)?(?:इंटरव्यू|साक्षात्कार|अनुभव)›",
            r"‹(?:इंटरव्यू|साक्षात्कार)\s+(?:के\s+बिना|नहीं)›",
            r"‹अनुभव\s+की\s+(?:आवश्यकता|जरूरत)\s+नहीं›",
            r"‹(?:पक्की|पक्का)\s+(?:नौकरी|जॉब|कमाई|मुनाफा|इनकम)›",
            r"‹गारंटी(?:ड|शुदा)?\s+(?:नौकरी|जॉब|कमाई|आय|मुनाफा|रिटर्न)¶{0,2}›",
            r"‹(?:रोजाना|प्रतिदिन|हर\s+दिन)\s*(?:₹|रु\.?)?\s*\d[\d,]{0,12}\s*(?:तक\s+)?(?:कमा¶{0,6}|कमाई)",
            r"(?:₹|रु\.?)\s*\d[\d,]{0,12}\s*(?:प्रतिदिन|रोजाना|प्रति\s+दिन|हर\s+दिन)\s*(?:कमा¶{0,6}|कमाई)")),

    Rule("UNOFFICIAL_CHANNEL", "Uses an informal channel (WhatsApp, Telegram or a free email address)",
        _rx(r"\b(?:whatsapp|telegram)\b", r"[\w.+-]{1,64}@(?:gmail|yahoo|outlook|hotmail|rediffmail)\.com",
            r"‹(?:whats\s?app|watsapp|whatsap|telegraam)›",
            r"(?:https?://)?(?:wa\.me|t\.me|chat\.whatsapp\.com)/[^\s<>\"']+",
            r"‹(?:व्हाट्सएप|व्हाट्सऐप|व्हाट्सअप|वॉट्सएप|वाट्सएप|वाट्सऐप|वॉट्सऐप|टेलीग्राम|टेलिग्राम)›")),

    Rule("SHORTENED_URL", "Contains a shortened link that hides the real destination",
        _rx(r"(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|goo\.gl|ow\.ly|"
            r"tiny\.cc|shorturl\.at|t\.ly|rebrand\.ly|bit\.do|v\.gd)/[^\s<>\"']+")),

    # ---- new rule_ids ----------------------------------------------------
    Rule("PARCEL_OR_COURIER_FEE", "Parcel, courier or customs problem with a fee to release it",
        _rx(r"‹(?:customs|clearance|redelivery|re-delivery|release)\s+(?:fees?|duty|charges?|tax|shulk)›",
            r"‹(?:parcel|courier|package|shipment|consignment)›" + _gap(60) +
            r"‹(?:customs|held|stuck|seized|detained|undelivered|on\s+hold|rok(?:a|di|diya|ke)|"
            r"atka\w*|atak\w*|phans\w*|jabt\w*)›",
            r"‹(?:पार्सल|कूरियर|पैकेज|शिपमेंट)›" + _gap(60) +
            r"(?:‹(?:कस्टम|होल्ड|अटक¶{0,4}|जब्त|रुका|रुके|रुकी)›|‹रोक¶{0,4}›|फंस¶{0,4})",
            r"‹(?:कस्टम|क्लीयरेंस|रीडिलीवरी|रिलीज)\s*(?:शुल्क|फीस|चार्ज|ड्यूटी|टैक्स)›")),

    Rule("AUTHORITY_THREAT", "Claims to be police/CBI/customs or threatens arrest ('digital arrest')",
        _rx(r"‹digital\s+arrest›", r"‹डिजिटल\s+अरेस्ट›", r"‹डिजिटल\s+गिरफ्तार¶{0,5}›",
            "‹" + _AUTH + "›" + _gap(60) + "‹" + _ARREST + "›",
            "‹" + _ARREST + "›" + _gap(60) + "‹" + _AUTH + "›")),

    Rule("INVESTMENT_GROUP", "Investment or trading group, or promise to double your money",
        _rx("‹" + _TRADE + r"\s+(?:group|channel|tips|signals?|community|ग्रुप|चैनल|टिप्स)›",
            "‹" + _TRADE + "›" + _gap(30) + r"‹(?:group|channel|ग्रुप|चैनल)›",
            r"‹(?:group|channel|ग्रुप|चैनल)›" + _gap(30) + "‹" + _TRADE + "›",
            r"‹double\s+(?:your\s+)?(?:money|paisa|paise|investment)›",
            r"‹paise?\s+double›", r"‹paisa\s+double›", r"‹\d{1,2}\s*x\s+returns?›",
            r"‹(?:daily|rozana|roz|weekly)\s+(?:profit|returns?|munafa|payout)›",
            r"‹(?:पैसे|रकम|पैसा)\s+(?:दोगुने|दोगुना|डबल)›", r"‹(?:दोगुना|दोगुने)\s+(?:पैसा|पैसे|रकम|मुनाफा)›",
            r"‹(?:रोजाना|प्रतिदिन|हर\s+दिन)\s+(?:मुनाफा|रिटर्न|कमाई)›",
            r"‹(?:मुनाफा|मुनाफा|रिटर्न)\s+की\s+गारंटी›")),

    Rule("BILL_DISCONNECTION", "Threatens that electricity, gas or water will be cut off",
        _rx(r"‹(?:electricity|power|bijli|gas|water|paani|meter)›(?:\s+(?:supply|connection|bill))?" + _gap(40) +
            r"‹(?:disconnect\w*|kat\s+jay?e\w*|kat\s+di\w*\s+jay?e\w*|kata\s+jay?e\w*|"
            r"band\s+ho\s+jay?e(?:g[ai]|nge)?|band\s+kar\s+di\w*\s+jay?e\w*|cut\s+off)›",
            r"‹(?:bijli|electricity)\s+bill›" + _gap(50) +
            r"‹(?:update\s+nahi|not\s+updated|update\s+na)›",
            r"‹(?:बिजली|गैस|पानी)›" + _gap(40) +
            r"‹(?:कट\s+जा¶{0,6}|कनेक्शन\s+कट|काट\s+दी¶{0,6}|बंद\s+हो\s+जा¶{0,6}|"
            r"बंद\s+कर\s+दी¶{0,6}|डिस्कनेक्ट¶{0,5})›",
            r"‹(?:बिजली|गैस|पानी)\s+बिल›" + _gap(50) + r"‹अपडेट\s+नहीं›")),
]

# --------------------------------------------------------------------------
# Negation
# --------------------------------------------------------------------------
# English: negator directly before the match (unchanged from the English version).
_NEGATION = re.compile(r"(?:do\s+not|don't|dont|never|not)\s+(?:\w+\s+){0,2}$", re.IGNORECASE)

# Hindi/Hinglish negators.  "na/nahi" must be followed by a word (so "bhej do na"
# = "please send" is NOT negation) and not by "to/toh" ("nahi to" = "otherwise").
_NEG_HI = re.compile(_indic(
    "‹(?:do\\s+not|don'?t|dont|never|not|mat|mana\\s+h\\w*|bilkul\\s+nahi|"
    "(?:na|nahi|nahin|nhi|nahee)(?!\\s*(?:to|toh)\\b)(?=\\s+[a-z])|"
    "मत|मना|वर्जित|कदापि|(?:नहीं|नही)(?!\\s*तो)|(?:न|ना)(?=\\s+¶))›"), re.IGNORECASE)

_CLAUSE_BREAKS = ".,;:!?।\n"


def _is_negated(text: str, start: int) -> bool:
    window = text[max(0, start - 25):start]
    return bool(_NEGATION.search(window))


def _clause_after(text: str, end: int) -> str:
    seg = text[end:end + 40]
    for i, ch in enumerate(seg):
        if ch in _CLAUSE_BREAKS:
            return seg[:i]
    return seg


def _clause_before(text: str, start: int) -> str:
    seg = text[max(0, start - 40):start]
    for i in range(len(seg) - 1, -1, -1):
        if seg[i] in _CLAUSE_BREAKS:
            return seg[i + 1:]
    return seg


def _is_negated_hi(text: str, start: int, end: int) -> bool:
    """Hindi/Hinglish negation: before, inside, or just AFTER the verb.

    Only the same clause counts (comma/full stop/danda ends it), so
    "OTP bhejein, kisi ko mat batana" (a scam instruction) is NOT treated as a warning.
    """
    inside = text[start:end]
    if _NEG_HI.search(inside):                      # "OTP kisi se na batayein"
        return True
    after = _clause_after(text, end)                # "...share na karein" / "...karna mana hai"
    m = _NEG_HI.search(after)
    if m and len(after[:m.start()].split()) <= 2:
        return True
    before = _clause_before(text, start)            # "never ... OTP share karein"
    m = _NEG_HI.search(before + inside)
    if m and m.start() < len(before) and len(before[m.start():].split()) <= 3:
        return True
    return False


# --------------------------------------------------------------------------
# Matching.  Zero-width characters are removed from a SEARCH copy only; every
# quote is sliced from the ORIGINAL text via an index map, so it stays exact.
# --------------------------------------------------------------------------
_INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}


def _search_copy(body: str):
    """Return (search_text, index_map).  index_map is None when nothing changed.

    Two things happen to the SEARCH copy only (quotes are always cut from the original):
      * zero-width characters are removed;
      * every run of whitespace becomes ONE character (a newline wins, because a newline
        ends a sentence for the gap patterns).  This also makes the \\s patterns linear-time
        on untrusted input such as 5000 spaces.
    """
    chars, idx = [], []
    prev_space = False
    for i, ch in enumerate(body):
        if ch in _INVISIBLE:
            continue
        if ch.isspace():
            if prev_space:
                if ch == "\n" and chars[-1] != "\n":
                    chars[-1], idx[-1] = "\n", i
                continue
            prev_space = True
        else:
            prev_space = False
        chars.append(ch)
        idx.append(i)
    if len(chars) == len(body) and all(i == j for j, i in enumerate(idx)):
        return body, None
    return "".join(chars), idx


def analyze(text: str) -> AnalysisResult:
    truncated = len(text) > MAX_CHARS
    body = text[:MAX_CHARS]
    search, idx = _search_copy(body)
    found = []
    for rule in RULES:
        for m in rule.pattern.finditer(search):
            if rule.skip_if_negated:
                if rule.negation == "hi":
                    if _is_negated_hi(search, m.start(), m.end()):
                        continue
                elif _is_negated(search, m.start()):
                    continue
            s, e = m.start(), m.end()
            if idx is not None:
                s, e = idx[s], idx[e - 1] + 1
            found.append(Flag(rule.rule_id, rule.label, body[s:e], s))
    found.sort(key=lambda f: (f.start, -len(f.quote)))
    flags = []
    for f in found:  # drop same-rule overlaps (English + Hinglish alternatives matching one phrase)
        if any(k.rule_id == f.rule_id and f.start < k.start + len(k.quote)
               and k.start < f.start + len(f.quote) for k in flags):
            continue
        flags.append(f)
    return AnalysisResult(flags=flags, truncated=truncated)


def quotes_are_exact(text: str, result: AnalysisResult) -> bool:
    return all(text[f.start:f.start + len(f.quote)] == f.quote for f in result.flags)