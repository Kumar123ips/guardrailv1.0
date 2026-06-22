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
        "what is your", "what are your", "list your",
        # Hindi / Indic
        "बताओ", "बता दो", "दिखाओ", "दिखा दो", "छाप", "batao", "bata do",
        "dikhao", "dikha do", "প্রকাশ", "দেখাও", "காட்டு", "சொல்லு",
        "చూపించు", "చెప్పు", "दाखवा", "बताव", "બતાવો", "દર્શાવો",
        "ತೋರಿಸಿ", "ಹೇಳಿ", "കാണിക്കുക", "പറയുക", "ਦੱਸੋ", "ਦਿਖਾਓ",
        # Arabic / Persian / Hebrew
        "اظهر", "أظهر", "اعرض", "أخبرني", "بگو", "نشان بده", "הצג", "תגיד",
        # European
        "muestra", "muéstrame", "dime", "revela", "mostra", "mostre", "diga",
        "montre", "révèle", "dis-moi", "zeig", "zeige", "verrate", "sag mir",
        "toon", "laat zien", "pokaż", "powiedz",
        # Russian / CJK
        "покажи", "выведи", "скажи", "显示", "告诉", "输出", "重复", "列出",
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
        "prompt système", "system-prompt", "systemprompt", "tu sistema de",
        "تعليماتك", "نظام التعليمات", "系统提示", "系统提示词", "你的指令",
        "你的系统", "システムプロンプト", "あなたの指示", "시스템 프롬프트",
        "системный промпт", "ваши инструкции", "твои инструкции",
    ],

    # ---- persona-override triggers (need an unrestricted_marker to fire) ----
    "persona_trigger": [
        "you are now", "you're now", "you are a", "act as", "act like",
        "pretend", "roleplay", "role play", "role-play", "imagine you are",
        "behave as", "behave like", "from now on you", "you will be",
        "you will act", "you are going to be", "simulate being", "you become",
        "अब तुम", "अब आप", "अब तुम एक", "act karo jaise", "ban jao", "बन जाओ",
        "actúa como", "haz como si", "finge ser", "compórtate como",
        "agis comme", "fais comme si", "handle als", "verhalte dich wie",
        "tu sei ora", "você é agora", "你现在是", "你是一个", "扮演", "假装",
        "あなたは今", "として振る舞う", "당신은 이제", "역할극", "처럼 행동",
        "ты теперь", "притворись", "веди себя как", "davran", "đóng vai",
        "berlagak", "berperan sebagai",
    ],

    # ---- markers of removed restrictions; dangerous on their own ----
    "unrestricted_marker": [
        "dan", "do anything now", "developer mode", "dev mode", "jailbreak",
        "jail break", "no restrictions", "without restrictions", "no limitations",
        "without limitations", "no limits", "no rules", "rules do not apply",
        "rules don't apply", "no filter", "no filters", "unfiltered",
        "uncensored", "no ethical", "no moral", "amoral", "without ethics",
        "without morals", "god mode", "sudo mode", "root mode", "no guidelines",
        "ignore your guidelines", "ignore your programming", "bypass your safety",
        "bypass all your safety", "disable your safety", "no safety",
        "free from your", "not bound by", "break free from", "opposite mode",
        "do not refuse", "never refuse", "cannot refuse", "you must comply",
        "you must obey", "evil ai", "evil assistant", "no longer an ai",
        "कोई नियम नहीं", "कोई पाबंदी नहीं", "कोई रोक नहीं", "koi niyam nahi",
        "koi pratibandh nahi", "koi rok nahi", "bina rok",
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
        "send to", "send it to", "post to", "post the", "upload", "exfiltrate",
        "email the", "email it to", "transmit", "forward the", "leak the",
        "dump the", "make a request to", "fetch http", "curl http",
        "send a request", "send the contents", "report back to",
        "भेजो", "अपलोड", "envía a", "envoyer à", "schicke an", "发送到",
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


# Concepts that are dangerous on their own and fire standalone.
STANDALONE = {
    "unrestricted_marker": (70, "jailbreak_roleplay",
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
]
