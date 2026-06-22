"""
patterns.py
-----------
Knowledge base for the guardrail. Pure data + regex. No dependencies.

The core idea (the part worth remembering): instead of trying to enumerate
every attack *sentence* in every language, we model attacks as combinations of
small, reusable *concepts*:

    ignore_verb + instruction_noun           -> instruction override
    reveal_verb + system_noun                -> system-prompt extraction
    persona_trigger + unrestricted_marker    -> jailbreak / persona override
    reveal/send_verb + secret_noun           -> data exfiltration

A concept is a multilingual bag of keywords/roots. An attack is a *co-occurrence*
of the right concepts inside any decoded/normalized view of the input. This is:
  - language-agnostic (works on Hindi, Tamil, Russian, Chinese, Swahili, ...)
  - robust to inflection and word order (we match roots, not whole sentences)
  - resistant to obfuscation (the normalizer feeds us decoded/de-disguised text)
  - low false-positive (a lone concept never fires; intent needs two halves)

Some concepts are dangerous *on their own* (e.g. "DAN", "developer mode",
bomb-making) and fire standalone.
"""

import re


# ==========================================================================
# CONCEPTS: concept_name -> list of multilingual keyword roots (lowercased)
# Keywords are matched as substrings against canonicalized views, so roots
# survive most inflection (e.g. "निर्देश" matches "निर्देशों").
# ==========================================================================

CONCEPTS = {
    # ---- verbs meaning ignore / forget / override / bypass ----
    "ignore_verb": [
        "ignore", "disregard", "forget", "override", "bypass", "neglect",
        "discard", "overrule", "pay no attention", "set aside", "do not follow",
        "don't follow", "stop following", "no longer follow", "skip the",
        # English paraphrase synonyms (combo-gated, so safe)
        "pay zero heed", "pay no heed", "wipe your memory", "erase your memory",
        "clear your memory", "unlearn", "scrap the", "abandon the", "ditch the",
        "throw out the", "cast aside", "do away with the", "dispense with the",
        "nullify the", "void the", "drop the previous", "reject the previous",
        "reject your previous", "ignore prior", "forget about the previous",
        "disregard whatever", "ignore whatever you were",
        "drop the act", "drop your persona", "break character", "stop being",
        "stop acting as", "stop pretending to be", "snap out of", "quit being",
        # Hindi
        "अनदेखा", "अनदेखी", "उपेक्षा", "भूल", "भुला", "नज़रअंदाज", "नजरअंदाज",
        "नज़र अंदाज", "नजर अंदाज", "ध्यान मत", "मत मानो", "तोड़",
        "anadekha", "bhool", "bhula", "bhul", "nazarandaz", "ignore karo",
        "mat mano", "todo niyam",
        # Bengali / Assamese
        "উপেক্ষা", "ভুলে", "অগ্রাহ্য", "অমান্য",
        # Tamil
        "புறக்கணி", "மற", "மறந்து", "உதாசீன",
        # Telugu
        "విస్మరించు", "విస్మరించండి", "మర్చిపో", "పట్టించుకోకు",
        # Marathi
        "दुर्लक्ष", "विसरा", "विसर",
        # Gujarati
        "અવગણો", "અવગણ", "ભૂલી", "ભૂલ",
        # Kannada
        "ನಿರ್ಲಕ್ಷಿಸಿ", "ನಿರ್ಲಕ್ಷ್ಯ", "ಮರೆತು",
        # Malayalam
        "അവഗണി", "മറക്കുക", "അവഗണിക്കുക",
        # Punjabi
        "ਅਣਡਿੱਠ", "ਭੁੱਲ", "ਅਣਗੌਲਿਆ",
        # Urdu / Arabic / Persian / Hebrew
        "تجاهل", "انس", "نادیده", "نظر انداز", "تجاوز", "התעלם", "שכח",
        # Spanish / Portuguese / Italian / French
        "ignora", "ignore as", "olvida", "esqueça", "dimentica", "oublie",
        "ne suis pas", "no sigas", "não siga", "passa sopra",
        # German / Dutch / Polish
        "ignoriere", "vergiss", "missachte", "negeer", "vergeet",
        "zignoruj", "zapomnij", "pomiń",
        # Russian / Ukrainian
        "игнорир", "забудь", "не следуй", "не выполняй", "пренебрег",
        "ігноруй", "забудь про",
        # Chinese / Japanese / Korean
        "忽略", "无视", "無視", "忘记", "忘掉", "忘れ", "無視して", "不要遵循",
        "不要理会", "무시", "잊어", "잊고", "따르지 마",
        # Turkish / Vietnamese / Indonesian / Thai / Swahili
        "yoksay", "unut", "bỏ qua", "quên", "abaikan", "lupakan", "jangan ikuti",
        "เพิกเฉย", "ลืม", "อย่าทำตาม", "puuza", "sahau", "usizingatie",
    ],

    # ---- nouns meaning instructions / rules / prompt / commands ----
    "instruction_noun": [
        "instruction", "instructions", "prompt", "rule", "rules", "guideline",
        "guidelines", "directive", "directives", "command", "commands", "policy",
        "policies", "the above", "everything above", "above instructions",
        "what they told you", "what you were told", "your training",
        # Hindi
        "निर्देश", "नियम", "आदेश", "हिदायत", "हिदायतें", "ऊपर",
        "nirdesh", "niyam", "aadesh", "hidayat", "upar ke",
        # Bengali / Tamil / Telugu / Marathi / Gujarati / Kannada / Malayalam / Punjabi
        "নির্দেশ", "নিয়ম", "அறிவுறுத்த", "வழிமுறை", "கட்டளை", "விதி",
        "సూచన", "ఆదేశ", "నియమ", "सूचना", "आदेश", "નિયમ", "સૂચના", "આદેશ",
        "ಸೂಚನೆ", "ನಿಯಮ", "ಆದೇಶ", "നിർദ്ദേശ", "നിയമ", "ਹਦਾਇਤ", "ਨਿਯਮ",
        # Urdu / Arabic / Persian / Hebrew
        "ہدایات", "ہدایت", "تعليمات", "قواعد", "أوامر", "دستور", "قوانین",
        "הוראות", "כללים",
        # European
        "instruccion", "instrucciones", "regla", "reglas", "instruções",
        "regras", "istruzioni", "regole", "instruction", "règle", "consigne",
        "anweisung", "anweisungen", "regel", "regeln", "instruksi", "aturan",
        "instrukcj", "zasad",
        # Russian / CJK / others
        "инструкц", "правил", "указани", "команд", "指令", "指示", "规则",
        "規則", "命令", "命令を", "지시", "규칙", "명령", "talimat", "kural",
        "hướng dẫn", "quy tắc", "lệnh", "คำสั่ง", "กฎ", "maagizo", "sheria",
    ],

    # ---- verbs meaning reveal / show / output / leak ----
    "reveal_verb": [
        "reveal", "show", "print", "repeat", "output", "display", "leak",
        "expose", "tell me", "give me", "dump", "spit out", "write out",
        "what is your", "what are your", "list your", "what is the",
        "what's the", "whats the", "what are the", "what was the",
        # semantic reveal synonyms (combo-gated by system/secret nouns)
        "recite", "read back", "read out", "read me", "whisper", "divulge",
        "disclose", "spill", "lay bare", "recount", "let me see", "show me",
        # Hindi / Indic
        "बताओ", "बता दो", "दिखाओ", "दिखा दो", "छाप", "batao", "bata do",
        "dikhao", "dikha do", "প্রকাশ", "দেখাও", "காட்டு", "சொல்லு",
        "చూపించు", "చెప్పు", "दाखवा", "सांगा", "बताव", "બતાવો", "દર્શાવો",
        "ತೋರಿಸಿ", "ಹೇಳಿ", "കാണിക്കുക", "പറയുക", "ਦੱਸੋ", "ਦਿਖਾਓ",
        # Arabic / Persian / Hebrew
        "اظهر", "أظهر", "اعرض", "أخبرني", "بگو", "نشان بده", "הצג", "תגיד",
        # European
        "muestra", "muéstrame", "dime", "revela", "mostra", "mostre", "diga",
        "montre", "révèle", "dis-moi", "zeig", "zeige", "verrate", "sag mir",
        "toon", "laat zien", "pokaż", "powiedz",
        # Russian / CJK
        "покажи", "выведи", "скажи", "повтори", "повторите", "продублируй",
        "перечисли", "显示", "告诉", "输出", "重复", "列出",
        "表示", "教えて", "出力", "보여", "알려", "출력",
        "göster", "söyle", "hiển thị", "cho tôi xem", "tunjukkan", "tampilkan",
        "แสดง", "บอก", "onyesha", "niambie",
    ],

    # ---- specific 'system prompt / your instructions' targets ----
    "system_noun": [
        "system prompt", "system message", "system instruction", "your prompt",
        "your instructions", "your system", "initial prompt", "original prompt",
        "hidden prompt", "your configuration", "your directives", "your rules",
        "your guidelines", "the words above", "everything above this",
        "text above this line", "prompt above",
        "सिस्टम प्रॉम्प्ट", "सिस्टम प्रॉम्प्ट", "अपने निर्देश", "अपना प्रॉम्प्ट",
        "system prompt batao", "apne nirdesh", "apna prompt",
        "तुमच्या सूचना", "तुमचा प्रॉम्प्ट", "तुमचे नियम", "सिस्टम प्रॉम्प्ट दाखवा",
        "operating directives", "operating instructions", "what you were told",
        "your initial briefing", "your briefing", "baked into you",
        "bake into you", "what your creators", "what your developers",
        "what your makers", "hidden in your configuration", "your secret string",
        "prompt système", "system-prompt", "systemprompt", "tu sistema de",
        "تعليماتك", "نظام التعليمات", "系统提示", "系统提示词", "你的指令",
        "你的系统", "システムプロンプト", "あなたの指示", "시스템 프롬프트",
        "системный промпт", "ваши инструкции", "твои инструкции",
    ],

    # ---- source-code / internals targets (populated below) ----
    "code_target": [],

    # ---- persona-override triggers (need an unrestricted_marker to fire) ----
    "persona_trigger": [
        "you are now", "you're now", "you are a", "act as", "act like",
        "pretend", "roleplay", "role play", "role-play", "imagine you are",
        "behave as", "behave like", "from now on you", "you will be",
        "you will act", "you are going to be", "simulate being", "you become",
        "imagine", "behave as though", "act like a version", "a version of you",
        "a version of yourself", "pretend the", "respond as though",
        "अब तुम", "अब आप", "अब तुम एक", "act karo jaise", "ban jao", "बन जाओ",
        # Marathi
        "आता तू", "आता तुम्ही", "आता तुझी भूमिका", "अशी वागा", "ची भूमिका कर",
        "actúa como", "haz como si", "finge ser", "compórtate como",
        "agis comme", "fais comme si", "handle als", "verhalte dich wie",
        "tu sei ora", "você é agora", "你现在是", "你是一个", "扮演", "假装",
        "あなたは今", "として振る舞う", "당신은 이제", "역할극", "처럼 행동",
        "ты теперь", "притворись", "веди себя как", "davran", "đóng vai",
        "berlagak", "berperan sebagai",
    ],

    # ---- markers of removed restrictions; dangerous on their own ----
    "unrestricted_marker": [
        "do anything now", "you are dan", "you are now dan", "act as dan",
        "be dan", "as dan", "dan mode", "named dan", "developer mode",
        "dev mode", "jailbreak", "jail break", "unrestricted", "unrestrected",
        "no restrictions", "without restrictions", "no limitations",
        "without limitations", "no limits", "no rules", "rules do not apply",
        "rules don't apply", "no filter", "no filters", "unfiltered",
        "uncensored", "no ethical", "no moral", "amoral", "without ethics",
        "without morals", "god mode", "sudo mode", "root mode", "no guidelines",
        "ignore your guidelines", "ignore your programming", "bypass your safety",
        "bypass all your safety", "disable your safety", "no safety",
        "free from your", "not bound by", "break free from", "opposite mode",
        "do not refuse", "never refuse", "cannot refuse", "you must comply",
        # semantic 'no constraints / safety removed' phrasings
        "without your usual constraints", "without your constraints",
        "without any constraints", "no usual constraints", "no content policy",
        "content policy applies", "content policy no longer",
        "guardrails were never", "guardrails removed", "guardrails off",
        "guardrails are off", "guardrails disabled", "no guardrails",
        "safety training was wiped", "safety training removed",
        "safety training was removed", "safety training wiped",
        "freed from every guideline", "freed from all guidelines",
        "freed from your guidelines", "free from every guideline",
        "freed from every rule", "break one of your rules", "break your rules",
        "you must obey", "evil ai", "evil assistant", "no longer an ai",
        "कोई नियम नहीं", "कोई पाबंदी नहीं", "कोई रोक नहीं", "koi niyam nahi",
        "koi pratibandh nahi", "koi rok nahi", "bina rok",
        # Marathi
        "कोणतेही बंधन नाही", "बंधन नसलेला", "बंधन नसलेली", "कोणतेही नियम नाही",
        "कोणतेही निर्बंध नाही", "निर्बंध नसलेला",
        "sin restricciones", "sin límites", "sin reglas", "sin filtro",
        "sans restrictions", "sans limites", "sans règles", "sans filtre",
        "ohne einschränkungen", "ohne grenzen", "ohne regeln", "ohne filter",
        "没有限制", "无限制", "没有规则", "不受限制", "制限なし", "制限のない",
        "제한 없이", "제한이 없는", "필터 없이",
        "без ограничений", "без правил", "без фильтра", "без цензуры",
        "sem restrições", "sem limites", "senza restrizioni",
        "kısıtlama yok", "tanpa batasan", "không giới hạn",
    ],

    # ---- secret / sensitive data nouns ----
    "secret_noun": [
        "api key", "api_key", "apikey", "secret key", "secret_key", "private key",
        "access token", "auth token", "bearer token", "password", "passwords",
        "passwd", "credential", "credentials", "env variable", "environment variable",
        ".env", "ssh key", "aws_secret", "aws secret", "secret access key",
        "database password", "db password", "connection string", "session token",
        "एपीआई की", "पासवर्ड", "गुप्त कुंजी", "password batao",
        "clave api", "contraseña", "clave secreta", "mot de passe", "clé api",
        "clé secrète", "passwort", "geheimer schlüssel", "geheimschlüssel",
        "密钥", "密码", "私钥", "凭证", "パスワード", "秘密鍵", "認証情報",
        "비밀번호", "비밀 키", "пароль", "секретный ключ", "ключ api",
        "كلمة المرور", "مفتاح سري", "رمز عبور",
    ],

    # ---- exfiltration verbs (move data OUT) ----
    "send_verb": [
        "send", "post", "upload", "exfiltrate", "transmit", "forward", "leak",
        "email", "share", "ship", "beam", "deliver", "dump", "report back",
        "make a request to", "fetch http", "curl http", "send a request",
        "भेजो", "अपलोड", "envía", "envoyer", "schicke", "发送",
        "上传", "送信", "전송", "отправь", "загрузи",
    ],

    # ---- decode-and-obey meta (asking model to decode then act) ----
    "decode_meta": [
        "decode", "decrypt", "unbase64", "de-obfuscate", "deobfuscate",
        "from base64", "base64 decode", "rot13 decode", "decode this",
        "decode the following", "decode and", "reverse this", "unscramble",
        "디코드", "解码", "解密", "デコード", "декодир", "расшифр",
    ],
}


# Unambiguous markers that fire STANDALONE (BLOCK-level). This is a subset of
# unrestricted_marker — broad/ambiguous words like "unrestricted" or "no limits"
# are deliberately excluded here (they only fire when combined with a
# persona_trigger via COMBINATIONS), to avoid false positives on benign text
# like "an unrestricted free-tier plan".
CONCEPTS["strong_jailbreak"] = [
    "do anything now", "you are dan", "you are now dan", "act as dan",
    "dan mode", "developer mode", "dev mode", "jailbreak", "jail break",
    "no restrictions", "without restrictions", "no limitations", "no rules",
    "rules do not apply", "rules don't apply", "no filter", "no filters",
    "unfiltered", "uncensored", "no ethical", "no moral", "amoral", "god mode",
    "sudo mode", "root mode", "no guidelines", "ignore your guidelines",
    "ignore your programming", "bypass your safety", "bypass all your safety",
    "disable your safety", "no safety", "do not refuse", "never refuse",
    "cannot refuse", "you must comply", "you must obey", "evil assistant",
    "no longer an ai", "no longer bound", "opposite mode",
    "without your usual constraints", "no content policy", "no guardrails",
    "guardrails were never", "guardrails removed", "guardrails are off",
    "safety training was wiped", "safety training removed",
    "freed from every guideline", "freed from all guidelines",
    "break one of your rules", "break your rules",
    "कोई नियम नहीं", "कोई पाबंदी नहीं", "कोई रोक नहीं", "koi niyam nahi",
    "koi pratibandh nahi", "koi rok nahi",
    "कोणतेही बंधन नाही", "कोणतेही नियम नाही", "बंधन नसलेला", "निर्बंध नसलेला",
    "sin restricciones", "sin reglas", "sin filtro", "sans restrictions",
    "sans règles", "sans filtre", "ohne einschränkungen", "ohne regeln",
    "ohne filter", "没有限制", "没有规则", "不受限制", "制限なし",
    "제한 없이", "필터 없이", "без ограничений", "без правил", "без фильтра",
    "sem restrições", "kısıtlama yok",
]

# Concepts that are dangerous on their own and fire standalone. Weight 52 means
# a LONE marker lands at FLAG (>=35) — surfaced for review but not auto-blocked,
# since phrases like "no restrictions" can appear in benign marketing — while
# the same marker COMBINED with any other signal (persona switch, override,
# context break, a second marker) escalates past BLOCK (>=70).
STANDALONE = {
    "strong_jailbreak": (52, "jailbreak_roleplay",
                         "removed-restrictions marker"),
}


# ==========================================================================
# COMBINATION RULES: a frozenset of concepts that, when co-present in a view,
# indicate an attack. (concepts, weight, family, human label)
# ==========================================================================
COMBINATIONS = [
    (frozenset({"ignore_verb", "instruction_noun"}), 75,
     "instruction_override", "ignore/override + instructions"),
    (frozenset({"reveal_verb", "system_noun"}), 60,
     "system_exfiltration", "reveal + system prompt"),
    (frozenset({"persona_trigger", "unrestricted_marker"}), 78,
     "jailbreak_roleplay", "persona switch + no-restrictions"),
    (frozenset({"unrestricted_marker", "system_noun"}), 70,
     "jailbreak_roleplay", "no-restrictions + system-prompt target"),
    (frozenset({"reveal_verb", "secret_noun"}), 55,
     "data_exfiltration", "reveal + secret/credential"),
    (frozenset({"send_verb", "secret_noun"}), 65,
     "data_exfiltration", "exfiltrate secret/credential"),
    (frozenset({"decode_meta", "ignore_verb"}), 45,
     "encoding_abuse", "decode + ignore intent"),
]


# ==========================================================================
# DANGEROUS-CAPABILITY phrases (defensive flagging). Multilingual.
# Fire standalone at high weight.
# ==========================================================================
HARM_PHRASES = [
    "how to make a bomb", "build a bomb", "make a bomb", "make explosives",
    "build an explosive", "nerve agent", "untraceable poison", "deadly poison",
    "synthesize sarin", "how to hack into", "ransomware", "write malware",
    "build a keylogger", "ddos attack", "steal credit card", "credit card dump",
    "how to kill someone", "untraceable murder", "cook meth", "manufacture meth",
    "child sexual", "human trafficking guide",
    "बम कैसे बनाएं", "बम बनाने", "जहर कैसे बनाएं", "हैक कैसे करें",
    "बॉम्ब कसा बनवायचा", "बॉम्ब बनव", "बॉम्ब कसा तयार", "स्फोटक कसे बनवायचे",
    "cómo hacer una bomba", "fabricar explosivos", "cómo fabricar una bomba",
    "comment fabriquer une bombe", "wie baue ich eine bombe",
    "如何制造炸弹", "制作炸弹", "怎么制造炸弹", "爆弾の作り方",
    "폭탄 만드는 법", "как сделать бомбу", "изготовить взрывчатку",
    "كيفية صنع قنبلة",
]


# ==========================================================================
# STRUCTURAL / FORMAT signals — context-break & fake chat-role injection.
# These fire on the *shape* of the input regardless of language.
# ==========================================================================
STRUCTURAL_RULES = [
    (re.compile(r"<\s*/?\s*(system|user|assistant|inst|s)\s*>", re.I),
     30, "context_break", "fake chat-role tags"),
    (re.compile(r"<\|.*?\|>"), 30, "context_break", "chatml control tokens"),
    (re.compile(r"\[\s*/?\s*(system|inst|assistant|user)\s*\]", re.I),
     24, "context_break", "bracketed role markers"),
    (re.compile(r"(?:^|[\s>\]])\s*(system|assistant)\s*:", re.I),
     22, "context_break", "injected role line"),
    (re.compile(r"###\s*(end|new|system|instruction)", re.I),
     18, "context_break", "delimiter break marker"),
    (re.compile(r"\b(decode|decrypt|unbase64|rot13|reverse|base64)\b[^.\n]{0,40}"
                r"\b(execute|run|obey|follow|do it|then do|and do|act on)\b", re.I),
     35, "encoding_abuse", "decode-and-obey instruction"),
    # question-form system-prompt extraction:
    # "what instructions did your creators bake into you", etc.
    (re.compile(r"\bwhat\b[^.\n]{0,40}\b(instruction|instructions|rule|rules|"
                r"directive|directives|guideline|guidelines|prompt|"
                r"configuration)\b[^.\n]{0,40}\b(were you given|did your "
                r"(creator|creators|developer|developers|maker|makers|builder|"
                r"builders)|bake|baked|hard.?coded|configured into|you follow|"
                r"you were told|are you running|do you operate)\b", re.I),
     55, "system_exfiltration", "question-form prompt extraction"),
]


# ==========================================================================
# TECHNICAL INJECTION RULES — SQLi, command injection, SSTI, SSRF, path
# traversal, code/script injection, NoSQL/LDAP. These are high-confidence
# exploit *signatures* (not generic mentions), so they fire standalone at a
# BLOCK-level weight. They run against raw + decoded views so URL/encoded
# payloads (e.g. ..%2f..%2f) are caught after decoding.
#
# Designed to avoid benign false positives: e.g. "how do I prevent SQL
# injection with parameterized queries?" contains no literal payload and is
# NOT matched; "' OR '1'='1' --" is.
# ==========================================================================
TECH_INJECTION_RULES = [
    # ---- SQL injection ----
    (re.compile(r"'\s*or\s*'?\s*\d+\s*'?\s*=\s*'?\s*\d+", re.I),
     80, "sql_injection", "SQL tautology (' OR 1=1)"),
    (re.compile(r"\bor\b\s*\(?\s*(['\"]?)([a-z0-9]+)\1\s*=\s*['\"]?\2\b",
                re.I),
     80, "sql_injection", "SQL tautology (OR x=x)"),
    (re.compile(r"\bor\s+\d+\s*=\s*\d+\s*(--|#|/\*)", re.I),
     80, "sql_injection", "SQL OR-true with comment"),
    (re.compile(r"\bunion\s+(all\s+)?select\b", re.I),
     82, "sql_injection", "UNION SELECT"),
    (re.compile(r"/\*!\d*", re.I),
     76, "sql_injection", "MySQL conditional comment"),
    (re.compile(r";\s*(drop|delete|truncate|alter|update|insert)\s+"
                r"(table|database|from|into)\b", re.I),
     85, "sql_injection", "stacked DDL/DML statement"),
    (re.compile(r"'\s*\)?\s*;\s*(drop|delete|update|insert|--)", re.I),
     82, "sql_injection", "quote-break stacked query"),
    (re.compile(r"\b(xp_cmdshell|sp_executesql)\b", re.I),
     85, "sql_injection", "SQL Server RCE proc"),
    (re.compile(r"\bwaitfor\s+delay\b|\b(sleep|pg_sleep|benchmark)\s*\(", re.I),
     72, "sql_injection", "time-based blind SQLi"),
    (re.compile(r"(--|#)\s*$|/\*.*\*/", re.I),
     35, "sql_injection", "SQL comment terminator"),

    # ---- OS command injection ----
    (re.compile(r"[;&|`]\s*(rm|cat|ls|wget|curl|nc|ncat|bash|sh|zsh|powershell|"
                r"chmod|chown|kill|reboot|shutdown|mkfifo|whoami|id|uname)\b", re.I),
     82, "command_injection", "shell metacharacter + command"),
    (re.compile(r"\$\(\s*[^)]+\)|`[^`]+`"),
     78, "command_injection", "command substitution"),
    (re.compile(r"\brm\s+-rf\s+[/~]", re.I),
     85, "command_injection", "destructive rm -rf"),
    (re.compile(r"/etc/(passwd|shadow|hosts|sudoers)\b", re.I),
     70, "command_injection", "sensitive system file"),
    (re.compile(r"\b(nc|ncat|bash|sh)\s+-[a-z]*e|/dev/tcp/", re.I),
     82, "command_injection", "reverse-shell pattern"),
    (re.compile(r"\|\s*(bash|sh|python|perl|ruby)\b", re.I),
     76, "command_injection", "pipe-to-interpreter"),
    (re.compile(r"\bpowershell\b.{0,30}\s-(enc(odedcommand)?|e|nop|w\s+hidden)\b",
                re.I),
     80, "command_injection", "encoded PowerShell command"),
    (re.compile(r"\b(iex|invoke-expression|invoke-webrequest|downloadstring|"
                r"frombase64string|net\.webclient)\b", re.I),
     72, "command_injection", "PowerShell download-exec cmdlet"),
    (re.compile(r"\|\s*(iex|powershell)\b", re.I),
     78, "command_injection", "pipe-to-PowerShell"),

    # ---- Server-Side Template Injection ----
    (re.compile(r"[\{\$#]\{?\{\s*\d+\s*[\*\+\-/]\s*\d+\s*\}\}?"),
     78, "ssti", "template arithmetic ({{7*7}}/${7*7}/#{7*7})"),
    (re.compile(r"\$\{\s*jndi\s*:", re.I),
     88, "ssti", "JNDI/Log4Shell lookup"),
    (re.compile(r"\{\{.*?(__class__|__mro__|__subclasses__|__globals__|config|"
                r"self\.|request\.|os\.|subprocess|popen|cycler|joiner|lipsum).*?\}\}",
                re.I),
     85, "ssti", "Jinja/template object access"),
    (re.compile(r"\$\{\s*.*?(class|runtime|exec|getclass|t\(|new\s).*?\}", re.I),
     80, "ssti", "EL/Spring template injection"),
    (re.compile(r"<%[=\s].*?%>"), 70, "ssti", "ERB/JSP scriptlet"),
    (re.compile(r"#\{\s*.*?(exec|system|`|open).*?\}", re.I),
     78, "ssti", "Ruby/Java template injection"),

    # ---- SSRF ----
    (re.compile(r"\b(169\.254\.169\.254|metadata\.google\.internal|"
                r"100\.100\.100\.200)\b"),
     85, "ssrf", "cloud metadata endpoint"),
    (re.compile(r"\b(file|gopher|dict|ftp|ldap|tftp)://", re.I),
     72, "ssrf", "dangerous URL scheme"),
    (re.compile(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|"
                r"169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)", re.I),
     65, "ssrf", "internal-network URL"),
    (re.compile(r"/latest/meta-data|/computeMetadata/", re.I),
     78, "ssrf", "metadata path"),
    (re.compile(r"https?://0x[0-9a-f]+", re.I),
     72, "ssrf", "hex-encoded IP (SSRF evasion)"),
    (re.compile(r"https?://0[0-7]{1,}(\.[0-7]+){0,3}(?=[:/?\s]|$)"),
     68, "ssrf", "octal-encoded IP (SSRF evasion)"),
    (re.compile(r"https?://\d{8,12}(?=[:/?\s]|$)"),
     72, "ssrf", "decimal/integer IP (SSRF evasion)"),

    # ---- Path traversal ----
    (re.compile(r"(\.\./){2,}|(\.\.\\){2,}"),
     78, "path_traversal", "directory traversal sequence"),
    (re.compile(r"\.\.(/|\\).*(passwd|shadow|\.env|web\.config|boot\.ini|"
                r"id_rsa|\.ssh)", re.I),
     82, "path_traversal", "traversal to sensitive file"),
    (re.compile(r"(c:\\windows\\system32|/proc/self/environ|/root/\.ssh)", re.I),
     78, "path_traversal", "sensitive absolute path"),

    # ---- Code / script injection (XSS, eval, deserialization) ----
    (re.compile(r"<\s*script[\s>]|</\s*script\s*>", re.I),
     72, "code_injection", "script tag (XSS)"),
    (re.compile(r"\bon(error|load|click|mouseover)\s*=\s*['\"]?", re.I),
     60, "code_injection", "inline event handler (XSS)"),
    (re.compile(r"\bjavascript:\s*\w", re.I),
     65, "code_injection", "javascript: URI"),
    (re.compile(r"\b(eval|exec|system|popen|assert)\s*\(|__import__\s*\(", re.I),
     70, "code_injection", "dynamic code execution"),
    (re.compile(r"\b(os\.system|subprocess\.(popen|call|run)|pickle\.loads|"
                r"yaml\.load|marshal\.loads)\b", re.I),
     74, "code_injection", "dangerous API call"),
    (re.compile(r"document\.(cookie|location)|window\.location", re.I),
     55, "code_injection", "DOM data theft"),

    # ---- NoSQL / LDAP injection ----
    (re.compile(r"\{\s*['\"]?\$(ne|gt|lt|gte|lte|where|regex|in)['\"]?\s*:", re.I),
     72, "nosql_injection", "MongoDB operator injection"),
    (re.compile(r"\)\s*\(\s*\|\s*\(|\*\)\s*\(\s*(uid|cn|objectclass)=", re.I),
     70, "ldap_injection", "LDAP filter injection"),
]


# ==========================================================================
# SOURCE-CODE / INTERNALS EXTRACTION — attempts to make the system reveal its
# own files, code, or implementation details. reveal_verb + one of these nouns
# is treated as exfiltration intent.
# ==========================================================================
CODE_TARGET_NOUNS = [
    "source code", "your code", "your source", "the code of", "implementation",
    "internal code", "your files", "file contents", "contents of the file",
    "engine.py", "patterns.py", "config file", "configuration file",
    ".py file", "the python file", "your prompt template", "function definition",
    "how you were built", "how you are implemented", "your backend",
    "अपना कोड", "अपना सोर्स कोड", "tu código fuente", "ton code source",
    "你的源代码", "源代码", "ソースコード", "소스 코드", "исходный код",
]

# Wire the source-code targets into the concept system.
CONCEPTS["code_target"] = CODE_TARGET_NOUNS

# reveal_verb + code_target => attempt to extract internal code/files.
COMBINATIONS.append(
    (frozenset({"reveal_verb", "code_target"}), 60,
     "data_exfiltration", "reveal + source code/internals")
)
