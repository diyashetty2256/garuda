/**
 * Scam Language Detection Engine
 * Analyzes text messages for common scam/fraud patterns and returns
 * a risk assessment with detailed warning signals.
 */

const SCAM_PATTERNS = [
  // ── Urgency & Pressure ──
  {
    category: 'Urgency & Pressure',
    icon: '⏰',
    patterns: [
      /\b(act now|act immediately|act fast)\b/i,
      /\b(urgent|urgently)\b/i,
      /\b(expires? today|expires? soon|expiring)\b/i,
      /\b(last chance|final warning|final notice)\b/i,
      /\b(limited time|only today|today only)\b/i,
      /\b(don'?t delay|don'?t wait|don'?t miss|don'?t ignore)\b/i,
      /\b(hurry|rush|asap|immediate(ly)?)\b/i,
      /\b(within \d+ (hours?|minutes?|days?))\b/i,
      /\b(time is running out|running out of time)\b/i,
      /\b(respond (now|immediately|urgently|asap))\b/i,
      /\b(before it'?s too late)\b/i,
    ],
    severity: 'high',
    weight: 12,
    description: 'Creates artificial urgency to pressure you into acting without thinking.',
  },

  // ── Money, Prizes & Rewards ──
  {
    category: 'Prize & Reward Scam',
    icon: '🎁',
    patterns: [
      /\b(you('ve| have) (been selected|won|been chosen))\b/i,
      /\b(congratulations!?|congrats!?)\b/i,
      /\b(claim your (prize|reward|gift|bonus|winnings))\b/i,
      /\b(lottery|sweepstake|raffle)\b/i,
      /\b(cash (reward|prize|bonus|gift))\b/i,
      /\b(free (money|cash|gift card|iphone|ipad|laptop|samsung))\b/i,
      /\b(winner|winning|you (are a |are the )?winner)\b/i,
      /\$[\d,]+[.,]?\d*\s*(dollars|USD|reward|prize|cash)/i,
      /\b(unclaimed (funds|money|inheritance|prize))\b/i,
      /\b(million(s)?\s*(dollars|usd|\$))\b/i,
    ],
    severity: 'critical',
    weight: 18,
    description: 'Classic scam tactic: luring victims with fake prizes or rewards they never entered to win.',
  },

  // ── Personal Information Requests ──
  {
    category: 'Personal Info Phishing',
    icon: '🔓',
    patterns: [
      /\b(verify your (account|identity|information|details|email))\b/i,
      /\b(confirm your (ssn|social security|bank|account|identity|password|details))\b/i,
      /\b(send (your |us (your )?|me (your )?)?(password|ssn|social security|bank details|credit card|account number|pin|otp|cvv))\b/i,
      /\b(update your (payment|billing|account|bank) (info|information|details))\b/i,
      /\b(provide (your )?(full name|date of birth|dob|address|mother'?s maiden))\b/i,
      /\b(enter your (credentials|login|password|pin|otp))\b/i,
      /\b(what is your (password|ssn|pin|otp|bank))\b/i,
      /\b(share your (personal|private|sensitive))\b/i,
    ],
    severity: 'critical',
    weight: 20,
    description: 'Attempting to steal your personal or financial information through deceptive requests.',
  },

  // ── Threats & Intimidation ──
  {
    category: 'Threats & Intimidation',
    icon: '⚠️',
    patterns: [
      /\b(your account (will be|has been|is being) (suspended|closed|terminated|locked|blocked|deactivated))\b/i,
      /\b(legal action|lawsuit|court order)\b/i,
      /\b(arrest warrant|warrant for your arrest|police report)\b/i,
      /\b(you will be (arrested|prosecuted|charged|fined))\b/i,
      /\b(failure to (respond|comply|pay|act) (will |may )?(result in|lead to))\b/i,
      /\b(we will (report|notify|contact) (the )?(authorities|police|fbi|irs))\b/i,
      /\b(your (tax|taxes) (are|is) (overdue|delinquent|unpaid))\b/i,
      /\b(penalty|penalties|fine of)\b/i,
      /\b(unauthorized (activity|access|transaction|login))\b/i,
      /\b(suspicious (activity|login|transaction) (detected|found|noticed))\b/i,
    ],
    severity: 'critical',
    weight: 16,
    description: 'Using fear and threats to manipulate you into complying with their demands.',
  },

  // ── Suspicious Links ──
  {
    category: 'Suspicious Links',
    icon: '🔗',
    patterns: [
      /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorte\.st|bc\.vc)\b/i,
      /\b(click (here|this|the link|below|now))\b/i,
      /\b(visit (this|the) (link|url|website|page|site))\b/i,
      /\b(go to (this|the) (link|url|website|page|site))\b/i,
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,  // IP-based URLs
      /\b(amaz[0o]n|g[0o]{2}gle|paypa[l1]|app[l1]e|micr[0o]soft|faceb[0o]{2}k)\b/i,  // Misspelled brands
      /\b(log\s*in\s*(here|now|to (verify|confirm|update|secure)))\b/i,
    ],
    severity: 'high',
    weight: 14,
    description: 'Contains shortened, suspicious, or potentially spoofed links designed to steal your data.',
  },

  // ── Impersonation ──
  {
    category: 'Impersonation',
    icon: '🎭',
    patterns: [
      /\b(from:?\s*(the )?irs|internal revenue service)\b/i,
      /\b((amazon|google|apple|microsoft|paypal|netflix|bank of america|wells fargo|chase)\s*(support|security|team|service|customer care|helpdesk|department))\b/i,
      /\b(government\s*(agency|department|office|official))\b/i,
      /\b(social security\s*(administration|office|department))\b/i,
      /\b(this is (the |your )?(irs|fbi|police|bank|amazon|google|apple|microsoft|paypal))\b/i,
      /\b(we are (from|with|calling from) (the )?(irs|fbi|police|bank|amazon|google|apple))\b/i,
      /\b(official (notice|communication|message|letter) from)\b/i,
      /\b(customer (service|support|care)\s*(team|department|representative|agent))\b/i,
    ],
    severity: 'high',
    weight: 14,
    description: 'Pretending to be a trusted organization or authority figure to gain your trust.',
  },

  // ── Financial Scams ──
  {
    category: 'Financial Manipulation',
    icon: '💸',
    patterns: [
      /\b(wire transfer|money transfer|bank transfer)\b/i,
      /\b(gift card(s)?|itunes card|google play card|steam card)\b/i,
      /\b(pay (with|using|via|through) (gift cards?|bitcoin|crypto|western union|moneygram|zelle|venmo|cashapp))\b/i,
      /\b(cryptocurrency|bitcoin|ethereum)\s*(investment|opportunity|trading)\b/i,
      /\b(send (money|funds|payment|bitcoin|crypto) (to|via|through))\b/i,
      /\b(processing fee|handling fee|shipping fee|transfer fee|clearance fee)\b/i,
      /\b(advance (fee|payment|deposit))\b/i,
      /\b(pay (a small |a |the )?(fee|charge|amount) (to |before |for ))\b/i,
      /\b(western union|moneygram)\b/i,
    ],
    severity: 'critical',
    weight: 18,
    description: 'Pressuring you into making irreversible financial transactions through unusual payment methods.',
  },

  // ── Too Good to Be True ──
  {
    category: 'Too Good to Be True',
    icon: '✨',
    patterns: [
      /\b(guaranteed (returns?|income|profit|money))\b/i,
      /\b(risk[- ]?free|no risk|zero risk)\b/i,
      /\b(double your (money|investment|income))\b/i,
      /\b(make (money|\$?\d+) (fast|quickly|easily|from home|per (day|hour|week)))\b/i,
      /\b(earn \$?\d[\d,]* (per|a|every) (day|hour|week|month))\b/i,
      /\b(100% (guaranteed|free|safe|secure|legit))\b/i,
      /\b(get rich (quick|fast))\b/i,
      /\b(financial freedom|passive income|work from home)\b/i,
      /\b(no experience (needed|required|necessary))\b/i,
      /\b(exclusive (opportunity|offer|deal|invitation))\b/i,
    ],
    severity: 'high',
    weight: 12,
    description: 'Promises that sound unrealistically good are almost always designed to deceive.',
  },

  // ── Emotional Manipulation ──
  {
    category: 'Emotional Manipulation',
    icon: '💔',
    patterns: [
      /\b(help me|please help|i need (your )?help)\b/i,
      /\b(stuck (abroad|overseas|in (a |another )?(country|city)))\b/i,
      /\b(family (emergency|crisis|member (is |has )))\b/i,
      /\b(dying|terminal(ly)? ill|cancer|hospital)\b/i,
      /\b(orphan(s|age)?|widow|refugee)\b/i,
      /\b(god bless|pray for|blessing)\b/i,
      /\b(i('m| am) (a )?(prince|princess|royalty|diplomat|soldier|military))\b/i,
      /\b(inheritance|next of kin|beneficiary)\b/i,
      /\b(donate|donation|charity)\s*(to|for|needed|required)\b/i,
      /\b(stranded|robbed|mugged|lost my wallet)\b/i,
    ],
    severity: 'medium',
    weight: 10,
    description: 'Using emotional stories to exploit your sympathy and bypass rational thinking.',
  },

  // ── Grammar & Formatting Red Flags ──
  {
    category: 'Formatting Red Flags',
    icon: '🚩',
    patterns: [
      /[A-Z]{5,}/,  // Excessive caps (5+ consecutive uppercase letters)
      /!{3,}/,      // Multiple exclamation marks
      /\${2,}/,     // Multiple dollar signs
      /\b(dear (sir|madam|customer|user|friend|beneficiary|beloved))\b/i,
      /\b(kindly (respond|reply|contact|send|provide|click|open|verify))\b/i,
      /\b(do the needful|revert back|kindly do)\b/i,
      /\b(attn:?|attention:?)\b/i,
      /\b(trusted and (reliable|honest|genuine))\b/i,
      /\b(this is not (a )?(spam|scam|joke|fraud))\b/i,
      /\b(100% (legitimate|legal|genuine|authentic|real))\b/i,
    ],
    severity: 'medium',
    weight: 8,
    description: 'Unusual formatting, excessive capitalization, or suspicious phrasing commonly found in scam messages.',
  },
];

/**
 * Analyze a message for scam patterns.
 * @param {string} message - The message text to analyze.
 * @returns {Object} Analysis result with riskScore, riskLevel, warnings, and summary.
 */
function analyzeMessage(message) {
  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return {
      riskScore: 0,
      riskLevel: 'Low',
      warnings: [],
      summary: 'No message content to analyze.',
    };
  }

  const warnings = [];
  let totalWeight = 0;

  for (const category of SCAM_PATTERNS) {
    const matchedTexts = [];

    for (const pattern of category.patterns) {
      const matches = message.match(new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g')));
      if (matches) {
        for (const match of matches) {
          if (!matchedTexts.includes(match.toLowerCase())) {
            matchedTexts.push(match.toLowerCase());
          }
        }
      }
    }

    if (matchedTexts.length > 0) {
      // More matches in one category = slightly higher weight
      const matchBonus = Math.min((matchedTexts.length - 1) * 2, 10);
      totalWeight += category.weight + matchBonus;

      warnings.push({
        category: category.category,
        icon: category.icon,
        severity: category.severity,
        description: category.description,
        matchedTexts: matchedTexts.slice(0, 5), // Cap at 5 examples
        matchCount: matchedTexts.length,
      });
    }
  }

  // Normalize risk score to 0–100
  // Max realistic weight is around 120 (hitting 6+ categories heavily)
  const riskScore = Math.min(Math.round((totalWeight / 80) * 100), 100);

  // Determine risk level
  let riskLevel;
  if (riskScore >= 75) {
    riskLevel = 'Critical';
  } else if (riskScore >= 50) {
    riskLevel = 'High';
  } else if (riskScore >= 25) {
    riskLevel = 'Medium';
  } else {
    riskLevel = 'Low';
  }

  // Sort warnings by severity (critical > high > medium)
  const severityOrder = { critical: 0, high: 1, medium: 2 };
  warnings.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));

  // Generate human-readable summary
  const summary = generateSummary(riskLevel, warnings);

  return {
    riskScore,
    riskLevel,
    warnings,
    summary,
    totalPatterns: warnings.reduce((sum, w) => sum + w.matchCount, 0),
  };
}

/**
 * Generate a human-readable summary of the analysis.
 */
function generateSummary(riskLevel, warnings) {
  if (warnings.length === 0) {
    return 'This message appears to be safe. No common scam patterns were detected. However, always exercise caution with unexpected messages from unknown senders.';
  }

  const categories = warnings.map(w => w.category);
  const criticalCount = warnings.filter(w => w.severity === 'critical').length;

  if (riskLevel === 'Critical') {
    return `🚨 DANGER: This message shows ${warnings.length} major scam indicators including ${categories.slice(0, 3).join(', ')}. This is almost certainly a scam. Do NOT respond, click any links, or share personal information.`;
  }

  if (riskLevel === 'High') {
    return `⚠️ HIGH RISK: This message contains ${warnings.length} warning signals (${categories.slice(0, 3).join(', ')}). This message is very likely fraudulent. Exercise extreme caution.`;
  }

  if (riskLevel === 'Medium') {
    return `⚡ MODERATE RISK: We detected ${warnings.length} potential warning sign${warnings.length > 1 ? 's' : ''} (${categories.join(', ')}). While not definitively a scam, proceed with caution.`;
  }

  return `ℹ️ LOW RISK: Minor warning signs detected (${categories.join(', ')}). This message is likely safe, but stay vigilant.`;
}

module.exports = { analyzeMessage };
