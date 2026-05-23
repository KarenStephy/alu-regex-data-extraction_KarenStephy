import re
import json
import os


# PATHS — always relative to this file, never the working dir

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE  = os.path.join(BASE_DIR, "..", "input",  "raw-text.txt")
OUTPUT_FILE = os.path.join(BASE_DIR, "..", "output", "sample-output.json")



# SECURITY: Patterns that indicate hostile input


HOSTILE_PATTERNS = [
    r"<script[\s\S]*?>[\s\S]*?</script>",      # XSS script injection
    r"javascript\s*:",                          # JS protocol in URLs
    r"(DROP|DELETE|INSERT|UPDATE)\s+TABLE",     # SQL DDL/DML injection
    r"'\s*OR\s*'1'\s*=\s*'1",                  # Classic SQL boolean bypass
    r";\s*--",                                  # SQL comment terminator
]

def is_hostile(text):
    """
    Scan raw text for known hostile/malicious patterns.
    Returns True if any suspicious content is detected.
    Security note: never trust raw input from external APIs.
    """
    for pattern in HOSTILE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False



# MASKING HELPERS (sensitive data protection)


def mask_card(card_number):
    """
    Mask credit card for safe output — only show last 4 digits.
    Security note: full card numbers must never appear in logs or output.
    e.g. 4111-1111-1111-1111 → **** **** **** 1111
    """
    digits = re.sub(r"\D", "", card_number)
    return "**** **** **** " + digits[-4:] if len(digits) >= 4 else "****"

def mask_email(email):
    """
    Partially mask email local part to reduce personal data exposure.
    e.g. john.mugisha@alumni.alueducation.com → jo***@alumni.alueducation.com
    """
    local, domain = email.rsplit("@", 1)
    masked_local = local[:2] + "***" if len(local) > 2 else "***"
    return f"{masked_local}@{domain}"



# REGEX PATTERNS


# 1. EMAILS
# Matches standard email format: local@domain.tld
# Local part: starts with alphanumeric, allows dots/underscores/hyphens
# Domain: at least one dot, TLD of 2+ letters
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9][\w.\-]*@[a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

# ALU-specific domain validators (order matters — most specific first)
ALU_SI      = re.compile(r"[\w.\-]+@si\.alueducation\.com$",      re.IGNORECASE)
ALU_ALUMNI  = re.compile(r"[\w.\-]+@alumni\.alueducation\.com$",  re.IGNORECASE)
ALU_OFFICIAL= re.compile(r"[\w.\-]+@alueducation\.com$",          re.IGNORECASE)

def classify_email(email):
    """
    Return the ALU category of an email address.
    Check SI and Alumni before Official to avoid prefix mis-matching.
    """
    if ALU_SI.match(email):
        return "ALU SI"
    if ALU_ALUMNI.match(email):
        return "ALU Alumni"
    if ALU_OFFICIAL.match(email):
        return "ALU Official"
    return "External"


#  2. CREDIT CARDS 
# Covers three real-world formats:
#   • Visa/Mastercard: 4 groups of 4 digits separated by space or hyphen
#   • AmEx:            4-6-5 digit groups  (15 digits total)
#   • Discover/plain:  16 consecutive digits with no separator
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}"   # Visa/MC: 4-4-4-4
    r"|\d{4}[\s\-]\d{6}[\s\-]\d{5}"                   # AmEx:    4-6-5
    r"|\d{16})\b"                                       # Discover: 16 raw digits
)

# Cards that are obviously invalid test values
INVALID_CARDS = {"0000000000000000"}

def luhn_check(card_number):
    """
    Validate a card number using the Luhn (mod-10) algorithm.
    This is the industry-standard checksum on all major payment cards.
    Returns True if the number is mathematically valid.
    """
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


#  3. URLs 
# Matches http and https URLs only.
# Deliberately excludes javascript: and data: (handled by hostile check).
URL_PATTERN = re.compile(r"https?://[^\s,\"'>]+", re.IGNORECASE)


#  4. PHONE NUMBERS
# Covers international formats seen in ALU support tickets:
#   +250 788 123 456   Rwanda (spaces)
#   +250-789-000-111   Rwanda (hyphens)
#   +49 30 1234 5678   Germany
#   +1 650 319 8930    USA
#   +254 700 123 456   Kenya
PHONE_PATTERN = re.compile(
    r"\+\d{1,3}[\s\-]\d{2,4}[\s\-]\d{3,4}[\s\-]?\d{3,4}"
)



# MAIN EXTRACTION LOGIC
def extract(text):
    """Run all four extraction passes and return structured results."""

    #  Emails
    emails_found = list(dict.fromkeys(EMAIL_PATTERN.findall(text)))  # dedupe

    # Simple validity check: must have proper TLD, no double dots, no @@
    def is_valid_email(e):
        if ".." in e or "@@" in e:
            return False
        parts = e.split("@")
        if len(parts) != 2:
            return False
        domain = parts[1]
        if not re.search(r"\.[a-zA-Z]{2,}$", domain):
            return False
        return True

    valid_emails = [e for e in emails_found if is_valid_email(e)]

    email_results = []
    for email in valid_emails:
        category = classify_email(email)
        email_results.append({
            "address":  email,
            "masked":   mask_email(email),
            "category": category
        })

    # Credit Cards
    cards_found = list(dict.fromkeys(CREDIT_CARD_PATTERN.findall(text)))
    card_results   = []
    invalid_cards  = []

    for card in cards_found:
        digits = re.sub(r"\D", "", card)
        if digits in INVALID_CARDS:
            invalid_cards.append({"masked": mask_card(card), "reason": "Known invalid test number"})
            continue
        if not luhn_check(card):
            invalid_cards.append({"masked": mask_card(card), "reason": "Failed Luhn checksum"})
            continue
        card_results.append({
            "masked": mask_card(card),
            "note":   "Raw PAN suppressed — PCI-DSS compliant"
        })
        #  URLs
    urls_found = list(dict.fromkeys(URL_PATTERN.findall(text)))
    url_results = [{"url": u} for u in urls_found]

    #  Phone Numbers
    phones_found = list(dict.fromkeys(PHONE_PATTERN.findall(text)))
    phone_results = [{"number": p} for p in phones_found]

    return {
        "emails":       email_results,
        "credit_cards": {"valid": card_results, "invalid": invalid_cards},
        "urls":         url_results,
        "phone_numbers": phone_results,
    }



# ENTRY POINT


def main():
    print("Reading input file...")
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_text = f.read()

    print("Running extraction and validation...")

    # Security check — scan before any extraction
    hostile_detected = is_hostile(raw_text)

    # Strip hostile lines so they never reach the regex engine
    if hostile_detected:
        clean_lines = []
        for line in raw_text.splitlines():
            if not is_hostile(line):
                clean_lines.append(line)
        raw_text = "\n".join(clean_lines)

    # Run extraction on cleaned text
    data = extract(raw_text)

    # Build final report
    report = {
        "security": {
            "hostile_input_detected": hostile_detected,
            "message": (
                "HOSTILE INPUT DETECTED: XSS, SQL injection, or JS URL found. "
                "Suspicious lines were stripped before extraction."
                if hostile_detected else "No hostile input detected."
            )
        },
        "data": data,
        "summary": {
            "emails_found":   len(data["emails"]),
            "credit_cards":   len(data["credit_cards"]["valid"]),
            "invalid_cards":  len(data["credit_cards"]["invalid"]),
            "urls_found":     len(data["urls"]),
            "phone_numbers":  len(data["phone_numbers"]),
        }
    }
    # Print summary to console (matches your original output style)
    print()
    print("  EXTRACTION SUMMARY")
    if hostile_detected:
        print(f"  [SECURITY] {report['security']['message']}")
    s = report["summary"]
    print(f"  Emails found   : {s['emails_found']}")
    print(f"  Credit cards   : {s['credit_cards']}  ({s['invalid_cards']} invalid/quarantined)")
    print(f"  URLs found     : {s['urls_found']}")
    print(f"  Phone numbers  : {s['phone_numbers']}")

    # Save JSON output (creates output folder if missing)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print()
    print(f"  Full output saved to: {os.path.abspath(OUTPUT_FILE)}")


if __name__ == "__main__":
    main()

