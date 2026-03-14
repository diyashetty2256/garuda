const express = require('express');
const path = require('path');
const { analyzeMessage } = require('./detector');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Dummy Scam Database ──
const SCAM_DATABASE = {
  phones: {
    '+18005551234': {
      isScam: true,
      type: 'Phone',
      reports: 847,
      firstReported: '2024-06-12',
      lastReported: '2026-03-10',
      category: 'IRS Impersonation',
      description: 'Caller claims to be from the IRS and threatens arrest if payment is not made immediately via gift cards.',
      riskLevel: 'Critical',
    },
    '+19175559876': {
      isScam: true,
      type: 'Phone',
      reports: 312,
      firstReported: '2025-01-20',
      lastReported: '2026-02-28',
      category: 'Tech Support Scam',
      description: 'Pretends to be Microsoft support, claims your computer is infected and asks for remote access.',
      riskLevel: 'High',
    },
    '+14155550199': {
      isScam: true,
      type: 'Phone',
      reports: 1203,
      firstReported: '2023-11-05',
      lastReported: '2026-03-12',
      category: 'Bank Fraud',
      description: 'Poses as your bank\'s fraud department, asks for account number and PIN to "secure" your account.',
      riskLevel: 'Critical',
    },
    '+12125557777': {
      isScam: true,
      type: 'Phone',
      reports: 95,
      firstReported: '2025-09-15',
      lastReported: '2026-01-05',
      category: 'Prize/Lottery Scam',
      description: 'Claims you won a lottery and need to pay a processing fee to collect your winnings.',
      riskLevel: 'High',
    },
    '+16505553456': {
      isScam: true,
      type: 'Phone',
      reports: 567,
      firstReported: '2024-03-22',
      lastReported: '2026-03-08',
      category: 'Social Security Scam',
      description: 'Threatens to suspend your Social Security number unless you verify personal details immediately.',
      riskLevel: 'Critical',
    },
  },
  emails: {
    'support@amaz0n-secure.com': {
      isScam: true,
      type: 'Email',
      reports: 2340,
      firstReported: '2024-02-14',
      lastReported: '2026-03-13',
      category: 'Phishing',
      description: 'Spoofed Amazon email asking to verify payment details via a fake login page.',
      riskLevel: 'Critical',
    },
    'winner@international-lottery.org': {
      isScam: true,
      type: 'Email',
      reports: 1578,
      firstReported: '2023-08-30',
      lastReported: '2026-02-15',
      category: 'Lottery Scam',
      description: 'Claims you\'ve won millions in an international lottery you never entered.',
      riskLevel: 'Critical',
    },
    'noreply@paypa1-security.com': {
      isScam: true,
      type: 'Email',
      reports: 890,
      firstReported: '2025-04-10',
      lastReported: '2026-03-11',
      category: 'PayPal Impersonation',
      description: 'Fake PayPal security alert requesting you confirm your account by entering credentials.',
      riskLevel: 'High',
    },
    'prince_mohammed@diplomats.ng': {
      isScam: true,
      type: 'Email',
      reports: 4521,
      firstReported: '2022-01-01',
      lastReported: '2026-03-01',
      category: 'Nigerian Prince / Advance Fee',
      description: 'Classic advance-fee scam promising millions in exchange for a small upfront payment.',
      riskLevel: 'Critical',
    },
    'helpdesk@micr0soft-support.com': {
      isScam: true,
      type: 'Email',
      reports: 672,
      firstReported: '2025-07-18',
      lastReported: '2026-03-09',
      category: 'Tech Support Phishing',
      description: 'Impersonates Microsoft support, attaches malware disguised as a security update.',
      riskLevel: 'High',
    },
  },
};

// ── API: Analyze a suspicious message ──
app.post('/api/analyze', (req, res) => {
  try {
    const { message } = req.body;

    if (!message || typeof message !== 'string') {
      return res.status(400).json({
        error: 'Please provide a message to analyze.',
      });
    }

    if (message.trim().length === 0) {
      return res.status(400).json({
        error: 'The message cannot be empty.',
      });
    }

    if (message.length > 10000) {
      return res.status(400).json({
        error: 'Message is too long. Please keep it under 10,000 characters.',
      });
    }

    const result = analyzeMessage(message);
    res.json(result);
  } catch (err) {
    console.error('Analysis error:', err);
    res.status(500).json({
      error: 'An error occurred while analyzing the message.',
    });
  }
});

// ── API: Lookup a phone number or email ──
app.post('/api/lookup', (req, res) => {
  try {
    const { query } = req.body;

    if (!query || typeof query !== 'string' || query.trim().length === 0) {
      return res.status(400).json({
        error: 'Please provide a phone number or email to look up.',
      });
    }

    const input = query.trim().toLowerCase();

    // Determine if it's an email or phone
    const isEmail = input.includes('@');
    let found = null;

    if (isEmail) {
      // Search emails (case-insensitive)
      for (const [email, data] of Object.entries(SCAM_DATABASE.emails)) {
        if (email.toLowerCase() === input) {
          found = { query: email, ...data };
          break;
        }
      }
    } else {
      // Normalize phone: strip everything except digits and leading +
      const normalized = input.replace(/[^+\d]/g, '');
      for (const [phone, data] of Object.entries(SCAM_DATABASE.phones)) {
        if (phone === normalized) {
          found = { query: phone, ...data };
          break;
        }
      }
    }

    if (found) {
      res.json({
        found: true,
        isScam: true,
        ...found,
      });
    } else {
      res.json({
        found: false,
        isScam: false,
        query: query.trim(),
        type: isEmail ? 'Email' : 'Phone',
        message: 'This ' + (isEmail ? 'email' : 'number') + ' has not been reported in our database. It may still be suspicious — always exercise caution.',
      });
    }
  } catch (err) {
    console.error('Lookup error:', err);
    res.status(500).json({
      error: 'An error occurred during the lookup.',
    });
  }
});

// ── Serve frontend ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start server ──
app.listen(PORT, () => {
  console.log(`🛡️  Scam Language Detector running at http://localhost:${PORT}`);
});
