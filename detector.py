"""
Scam Language Detection Engine
Analyzes text messages for common scam/fraud patterns and returns
a risk assessment with detailed warning signals.
"""

import re


SCAM_PATTERNS = [
    # -- Urgency & Pressure --
    {
        "category": "Urgency & Pressure",
        "patterns": [
            r"\b(act now|act immediately|act fast)\b",
            r"\b(urgent|urgently)\b",
            r"\b(expires? today|expires? soon|expiring)\b",
            r"\b(last chance|final warning|final notice)\b",
            r"\b(limited time|only today|today only)\b",
            r"\b(don'?t delay|don'?t wait|don'?t miss|don'?t ignore)\b",
            r"\b(hurry|rush|asap|immediate(ly)?)\b",
            r"\b(within \d+ (hours?|minutes?|days?))\b",
            r"\b(time is running out|running out of time)\b",
            r"\b(respond (now|immediately|urgently|asap))\b",
            r"\b(before it'?s too late)\b",
        ],
        "severity": "high",
        "weight": 12,
        "description": "Creates artificial urgency to pressure you into acting without thinking.",
    },

    # -- Money, Prizes & Rewards --
    {
        "category": "Prize & Reward Scam",
        "patterns": [
            r"\b(you('ve| have) (been selected|won|been chosen))\b",
            r"\b(congratulations!?|congrats!?)\b",
            r"\b(claim your (prize|reward|gift|bonus|winnings))\b",
            r"\b(lottery|sweepstake|raffle)\b",
            r"\b(cash (reward|prize|bonus|gift))\b",
            r"\b(free (money|cash|gift card|iphone|ipad|laptop|samsung))\b",
            r"\b(winner|winning|you (are a |are the )?winner)\b",
            r"\$[\d,]+[.,]?\d*\s*(dollars|USD|reward|prize|cash)",
            r"\b(unclaimed (funds|money|inheritance|prize))\b",
            r"\b(million(s)?\s*(dollars|usd|\$))\b",
        ],
        "severity": "critical",
        "weight": 18,
        "description": "Classic scam tactic: luring victims with fake prizes or rewards they never entered to win.",
    },

    # -- Personal Information Requests --
    {
        "category": "Personal Info Phishing",
        "patterns": [
            r"\b(verify your (account|identity|information|details|email))\b",
            r"\b(confirm your (ssn|social security|bank|account|identity|password|details))\b",
            r"\b(send (your |us (your )?|me (your )?)?(password|ssn|social security|bank details|credit card|account number|pin|otp|cvv))\b",
            r"\b(update your (payment|billing|account|bank) (info|information|details))\b",
            r"\b(provide (your )?(full name|date of birth|dob|address|mother'?s maiden))\b",
            r"\b(enter your (credentials|login|password|pin|otp))\b",
            r"\b(what is your (password|ssn|pin|otp|bank))\b",
            r"\b(share your (personal|private|sensitive))\b",
        ],
        "severity": "critical",
        "weight": 20,
        "description": "Attempting to steal your personal or financial information through deceptive requests.",
    },

    # -- Threats & Intimidation --
    {
        "category": "Threats & Intimidation",
        "patterns": [
            r"\b(your account (will be|has been|is being) (suspended|closed|terminated|locked|blocked|deactivated))\b",
            r"\b(legal action|lawsuit|court order)\b",
            r"\b(arrest warrant|warrant for your arrest|police report)\b",
            r"\b(you will be (arrested|prosecuted|charged|fined))\b",
            r"\b(failure to (respond|comply|pay|act) (will |may )?(result in|lead to))\b",
            r"\b(we will (report|notify|contact) (the )?(authorities|police|fbi|irs))\b",
            r"\b(your (tax|taxes) (are|is) (overdue|delinquent|unpaid))\b",
            r"\b(penalty|penalties|fine of)\b",
            r"\b(unauthorized (activity|access|transaction|login))\b",
            r"\b(suspicious (activity|login|transaction) (detected|found|noticed))\b",
        ],
        "severity": "critical",
        "weight": 16,
        "description": "Using fear and threats to manipulate you into complying with their demands.",
    },

    # -- Suspicious Links --
    {
        "category": "Suspicious Links",
        "patterns": [
            r"\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorte\.st|bc\.vc)\b",
            r"\b(click (here|this|the link|below|now))\b",
            r"\b(visit (this|the) (link|url|website|page|site))\b",
            r"\b(go to (this|the) (link|url|website|page|site))\b",
            r"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"\b(amaz[0o]n|g[0o]{2}gle|paypa[l1]|app[l1]e|micr[0o]soft|faceb[0o]{2}k)\b",
            r"\b(log\s*in\s*(here|now|to (verify|confirm|update|secure)))\b",
        ],
        "severity": "high",
        "weight": 14,
        "description": "Contains shortened, suspicious, or potentially spoofed links designed to steal your data.",
    },

    # -- Impersonation --
    {
        "category": "Impersonation",
        "patterns": [
            r"\b(from:?\s*(the )?irs|internal revenue service)\b",
            r"\b((amazon|google|apple|microsoft|paypal|netflix|bank of america|wells fargo|chase)\s*(support|security|team|service|customer care|helpdesk|department))\b",
            r"\b(government\s*(agency|department|office|official))\b",
            r"\b(social security\s*(administration|office|department))\b",
            r"\b(this is (the |your )?(irs|fbi|police|bank|amazon|google|apple|microsoft|paypal))\b",
            r"\b(we are (from|with|calling from) (the )?(irs|fbi|police|bank|amazon|google|apple))\b",
            r"\b(official (notice|communication|message|letter) from)\b",
            r"\b(customer (service|support|care)\s*(team|department|representative|agent))\b",
        ],
        "severity": "high",
        "weight": 14,
        "description": "Pretending to be a trusted organization or authority figure to gain your trust.",
    },

    # -- Financial Scams --
    {
        "category": "Financial Manipulation",
        "patterns": [
            r"\b(wire transfer|money transfer|bank transfer)\b",
            r"\b(gift card(s)?|itunes card|google play card|steam card)\b",
            r"\b(pay (with|using|via|through) (gift cards?|bitcoin|crypto|western union|moneygram|zelle|venmo|cashapp))\b",
            r"\b(cryptocurrency|bitcoin|ethereum)\s*(investment|opportunity|trading)\b",
            r"\b(send (money|funds|payment|bitcoin|crypto) (to|via|through))\b",
            r"\b(processing fee|handling fee|shipping fee|transfer fee|clearance fee)\b",
            r"\b(advance (fee|payment|deposit))\b",
            r"\b(pay (a small |a |the )?(fee|charge|amount) (to |before |for ))\b",
            r"\b(western union|moneygram)\b",
        ],
        "severity": "critical",
        "weight": 18,
        "description": "Pressuring you into making irreversible financial transactions through unusual payment methods.",
    },

    # -- Too Good to Be True --
    {
        "category": "Too Good to Be True",
        "patterns": [
            r"\b(guaranteed (returns?|income|profit|money))\b",
            r"\b(risk[- ]?free|no risk|zero risk)\b",
            r"\b(double your (money|investment|income))\b",
            r"\b(make (money|\$?\d+) (fast|quickly|easily|from home|per (day|hour|week)))\b",
            r"\b(earn \$?\d[\d,]* (per|a|every) (day|hour|week|month))\b",
            r"\b(100% (guaranteed|free|safe|secure|legit))\b",
            r"\b(get rich (quick|fast))\b",
            r"\b(financial freedom|passive income|work from home)\b",
            r"\b(no experience (needed|required|necessary))\b",
            r"\b(exclusive (opportunity|offer|deal|invitation))\b",
        ],
        "severity": "high",
        "weight": 12,
        "description": "Promises that sound unrealistically good are almost always designed to deceive.",
    },

    # -- Emotional Manipulation --
    {
        "category": "Emotional Manipulation",
        "patterns": [
            r"\b(help me|please help|i need (your )?help)\b",
            r"\b(stuck (abroad|overseas|in (a |another )?(country|city)))\b",
            r"\b(family (emergency|crisis|member (is |has )))\b",
            r"\b(dying|terminal(ly)? ill|cancer|hospital)\b",
            r"\b(orphan(s|age)?|widow|refugee)\b",
            r"\b(god bless|pray for|blessing)\b",
            r"\b(i('m| am) (a )?(prince|princess|royalty|diplomat|soldier|military))\b",
            r"\b(inheritance|next of kin|beneficiary)\b",
            r"\b(donate|donation|charity)\s*(to|for|needed|required)\b",
            r"\b(stranded|robbed|mugged|lost my wallet)\b",
        ],
        "severity": "medium",
        "weight": 10,
        "description": "Using emotional stories to exploit your sympathy and bypass rational thinking.",
    },

    # -- Grammar & Formatting Red Flags --
    {
        "category": "Formatting Red Flags",
        "patterns": [
            r"[A-Z]{5,}",
            r"!{3,}",
            r"\${2,}",
            r"\b(dear (sir|madam|customer|user|friend|beneficiary|beloved))\b",
            r"\b(kindly (respond|reply|contact|send|provide|click|open|verify))\b",
            r"\b(do the needful|revert back|kindly do)\b",
            r"\b(attn:?|attention:?)\b",
            r"\b(trusted and (reliable|honest|genuine))\b",
            r"\b(this is not (a )?(spam|scam|joke|fraud))\b",
            r"\b(100% (legitimate|legal|genuine|authentic|real))\b",
        ],
        "severity": "medium",
        "weight": 8,
        "description": "Unusual formatting, excessive capitalization, or suspicious phrasing commonly found in scam messages.",
    },
]


def analyze_message(message: str) -> dict:
    """Analyze a message for scam patterns."""
    if not message or not isinstance(message, str) or len(message.strip()) == 0:
        return {
            "riskScore": 0,
            "riskLevel": "Low",
            "warnings": [],
            "summary": "No message content to analyze.",
            "totalPatterns": 0,
        }

    warnings = []
    total_weight = 0

    for category in SCAM_PATTERNS:
        matched_texts = []

        for pattern in category["patterns"]:
            matches = re.findall(pattern, message, re.IGNORECASE)
            if matches:
                for match in matches:
                    # findall returns tuples for groups, flatten
                    text = match if isinstance(match, str) else match[0]
                    if text.lower() not in matched_texts:
                        matched_texts.append(text.lower())

        if matched_texts:
            match_bonus = min((len(matched_texts) - 1) * 2, 10)
            total_weight += category["weight"] + match_bonus

            warnings.append({
                "category": category["category"],
                "severity": category["severity"],
                "description": category["description"],
                "matchedTexts": matched_texts[:5],
                "matchCount": len(matched_texts),
            })

    # Normalize risk score to 0-100
    risk_score = min(round((total_weight / 80) * 100), 100)

    # Determine risk level
    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Sort warnings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    warnings.sort(key=lambda w: severity_order.get(w["severity"], 3))

    summary = _generate_summary(risk_level, warnings)
    total_patterns = sum(w["matchCount"] for w in warnings)

    return {
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "warnings": warnings,
        "summary": summary,
        "totalPatterns": total_patterns,
    }


def _generate_summary(risk_level: str, warnings: list) -> str:
    """Generate a human-readable summary of the analysis."""
    if not warnings:
        return (
            "This message appears to be safe. No common scam patterns were detected. "
            "However, always exercise caution with unexpected messages from unknown senders."
        )

    categories = [w["category"] for w in warnings]

    if risk_level == "Critical":
        return (
            f"DANGER: This message shows {len(warnings)} major scam indicators including "
            f"{', '.join(categories[:3])}. This is almost certainly a scam. "
            "Do NOT respond, click any links, or share personal information."
        )

    if risk_level == "High":
        return (
            f"HIGH RISK: This message contains {len(warnings)} warning signals "
            f"({', '.join(categories[:3])}). This message is very likely fraudulent. "
            "Exercise extreme caution."
        )

    if risk_level == "Medium":
        return (
            f"MODERATE RISK: We detected {len(warnings)} potential warning "
            f"sign{'s' if len(warnings) > 1 else ''} ({', '.join(categories)}). "
            "While not definitively a scam, proceed with caution."
        )

    return (
        f"LOW RISK: Minor warning signs detected ({', '.join(categories)}). "
        "This message is likely safe, but stay vigilant."
    )


# ══════════════════════════════════════
# Scam Contact Lookup Database (dummy)
# ══════════════════════════════════════

SCAM_CONTACTS = {
    # ── Phone numbers ──
    "+18005551234": {
        "category": "IRS Impersonation Scam",
        "description": "This number has been reported for impersonating IRS agents, threatening victims with arrest and demanding payment via gift cards.",
        "reports": 1247,
        "riskLevel": "Critical",
    },
    "+14155550199": {
        "category": "Tech Support Scam",
        "description": "Callers claim to be from Microsoft or Apple, insisting your computer is infected and requesting remote access.",
        "reports": 892,
        "riskLevel": "High",
    },
    "+919876543210": {
        "category": "Lottery / Prize Scam",
        "description": "Calls or texts claiming you've won a large prize and must pay a processing fee to collect your winnings.",
        "reports": 534,
        "riskLevel": "High",
    },

    # ── Email addresses ──
    "support@amaz0n-secure.com": {
        "category": "Phishing – Fake Amazon",
        "description": "Spoofed Amazon email used to steal login credentials and payment information through fake 'account verification' pages.",
        "reports": 3891,
        "riskLevel": "Critical",
    },
    "prince_mohammed@diplomats.ng": {
        "category": "Advance-Fee (419) Scam",
        "description": "Classic Nigerian prince email requesting bank details to transfer a large inheritance in exchange for an upfront fee.",
        "reports": 7432,
        "riskLevel": "Critical",
    },
    "security@paypa1-alerts.com": {
        "category": "Phishing – Fake PayPal",
        "description": "Fraudulent PayPal security alert email designed to harvest login credentials.",
        "reports": 2105,
        "riskLevel": "Critical",
    },
    "winner@lotteryglobal.info": {
        "category": "Lottery Scam",
        "description": "Sends fake lottery winning notifications requiring a 'processing fee' to release funds.",
        "reports": 1560,
        "riskLevel": "High",
    },
}


def lookup_contact(query: str) -> dict:
    """Look up a phone number or email in the scam contacts database."""
    if not query or not isinstance(query, str):
        return {"isScam": False, "query": query, "type": "unknown", "message": "Invalid query."}

    cleaned = query.strip().lower()

    # Determine type
    if "@" in cleaned:
        contact_type = "Email"
    else:
        # Normalize phone: strip spaces, dashes, parens
        cleaned = re.sub(r"[\s\-\(\).]", "", cleaned)
        contact_type = "Phone"

    # Search the database (case-insensitive keys)
    for key, info in SCAM_CONTACTS.items():
        normalized_key = key.strip().lower()
        if contact_type == "Phone":
            normalized_key = re.sub(r"[\s\-\(\).]", "", normalized_key)
        if cleaned == normalized_key:
            return {
                "isScam": True,
                "query": query.strip(),
                "type": contact_type,
                "category": info["category"],
                "description": info["description"],
                "reports": info["reports"],
                "riskLevel": info["riskLevel"],
            }

    return {
        "isScam": False,
        "query": query.strip(),
        "type": contact_type,
        "message": f"This {contact_type.lower()} has not been reported in our scam database. However, always remain cautious with unknown contacts.",
    }


# ══════════════════════════════════════
# India Scam Heatmap Data (dummy)
# ══════════════════════════════════════

# Each entry: [lat, lng, intensity, city_name, state, report_count]
SCAM_HEATMAP_DATA = [
    {"lat": 28.6139, "lng": 77.2090, "intensity": 0.95, "city": "Delhi", "state": "Delhi", "reports": 14520},
    {"lat": 19.0760, "lng": 72.8777, "intensity": 0.92, "city": "Mumbai", "state": "Maharashtra", "reports": 13200},
    {"lat": 12.9716, "lng": 77.5946, "intensity": 0.88, "city": "Bengaluru", "state": "Karnataka", "reports": 11800},
    {"lat": 13.0827, "lng": 80.2707, "intensity": 0.82, "city": "Chennai", "state": "Tamil Nadu", "reports": 9450},
    {"lat": 22.5726, "lng": 88.3639, "intensity": 0.85, "city": "Kolkata", "state": "West Bengal", "reports": 10200},
    {"lat": 17.3850, "lng": 78.4867, "intensity": 0.80, "city": "Hyderabad", "state": "Telangana", "reports": 8900},
    {"lat": 23.0225, "lng": 72.5714, "intensity": 0.78, "city": "Ahmedabad", "state": "Gujarat", "reports": 7650},
    {"lat": 18.5204, "lng": 73.8567, "intensity": 0.76, "city": "Pune", "state": "Maharashtra", "reports": 7200},
    {"lat": 26.9124, "lng": 75.7873, "intensity": 0.72, "city": "Jaipur", "state": "Rajasthan", "reports": 6100},
    {"lat": 26.8467, "lng": 80.9462, "intensity": 0.70, "city": "Lucknow", "state": "Uttar Pradesh", "reports": 5800},
    {"lat": 21.1702, "lng": 72.8311, "intensity": 0.65, "city": "Surat", "state": "Gujarat", "reports": 4900},
    {"lat": 23.2599, "lng": 77.4126, "intensity": 0.60, "city": "Bhopal", "state": "Madhya Pradesh", "reports": 4200},
    {"lat": 25.3176, "lng": 82.9739, "intensity": 0.58, "city": "Varanasi", "state": "Uttar Pradesh", "reports": 3900},
    {"lat": 30.7333, "lng": 76.7794, "intensity": 0.68, "city": "Chandigarh", "state": "Chandigarh", "reports": 5100},
    {"lat": 15.2993, "lng": 74.1240, "intensity": 0.45, "city": "Goa", "state": "Goa", "reports": 2100},
    {"lat": 11.0168, "lng": 76.9558, "intensity": 0.62, "city": "Coimbatore", "state": "Tamil Nadu", "reports": 4500},
    {"lat": 9.9312, "lng": 76.2673, "intensity": 0.55, "city": "Kochi", "state": "Kerala", "reports": 3400},
    {"lat": 25.6093, "lng": 85.1376, "intensity": 0.52, "city": "Patna", "state": "Bihar", "reports": 3100},
    {"lat": 21.1458, "lng": 79.0882, "intensity": 0.58, "city": "Nagpur", "state": "Maharashtra", "reports": 3800},
    {"lat": 31.1048, "lng": 77.1734, "intensity": 0.40, "city": "Shimla", "state": "Himachal Pradesh", "reports": 1800},
    {"lat": 20.2961, "lng": 85.8245, "intensity": 0.50, "city": "Bhubaneswar", "state": "Odisha", "reports": 2800},
    {"lat": 26.4499, "lng": 80.3319, "intensity": 0.55, "city": "Kanpur", "state": "Uttar Pradesh", "reports": 3500},
    {"lat": 22.7196, "lng": 75.8577, "intensity": 0.48, "city": "Indore", "state": "Madhya Pradesh", "reports": 2600},
    {"lat": 28.4595, "lng": 77.0266, "intensity": 0.75, "city": "Gurugram", "state": "Haryana", "reports": 6800},
    {"lat": 28.5355, "lng": 77.3910, "intensity": 0.73, "city": "Noida", "state": "Uttar Pradesh", "reports": 6200},
]

# In-memory store for user-submitted reports
_user_reports = []


def get_heatmap_data() -> list:
    """Return heatmap data points for the India scam map."""
    return SCAM_HEATMAP_DATA


def get_report_stats() -> dict:
    """Return aggregate statistics for the dashboard."""
    total_reports = sum(city["reports"] for city in SCAM_HEATMAP_DATA) + len(_user_reports)
    top_city = max(SCAM_HEATMAP_DATA, key=lambda c: c["reports"])
    top_states = {}
    for city in SCAM_HEATMAP_DATA:
        top_states[city["state"]] = top_states.get(city["state"], 0) + city["reports"]
    most_affected_state = max(top_states, key=top_states.get)

    return {
        "totalReports": total_reports,
        "citiesCovered": len(SCAM_HEATMAP_DATA),
        "topCity": top_city["city"],
        "topCityReports": top_city["reports"],
        "mostAffectedState": most_affected_state,
        "mostAffectedStateReports": top_states[most_affected_state],
        "userReports": len(_user_reports),
    }


def submit_report(report: dict) -> dict:
    """Submit a new scam report."""
    required = ["type", "contact", "category", "description"]
    for field in required:
        if field not in report or not report[field]:
            return {"success": False, "error": f"Missing required field: {field}"}

    _user_reports.append({
        "type": report["type"],
        "contact": report["contact"],
        "category": report["category"],
        "description": report["description"],
    })

    return {"success": True, "message": "Thank you! Your report has been submitted successfully."}
