import json
import re
import sqlite3
import hashlib
import os
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

client = OpenAI()
DB_PATH = "phishing_reports.db"

app = FastAPI(
    title="KI Phishing Checker API",
    description="API für automatische E-Mail-Analyse und spätere Browser-Extension.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Für lokale Tests. Später einschränken.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    email_text: str
    source: Optional[str] = "api"
    beta_code: Optional[str] = None




class BetaVerifyRequest(BaseModel):
    beta_code: Optional[str] = None


class AnalyzeResponse(BaseModel):
    score: int
    label: str
    level: str
    risks: List[str]
    mapped_risks: List[str]
    reason: str
    recommendation: str
    primary_domain: str
    links: List[str]
    domain_count: int
    domain_count_last_24h: int
    exact_mail_count: int


class ReportRequest(BaseModel):
    email_text: str
    score: int
    label: str
    mapped_risks: List[str]
    beta_code: Optional[str] = None


class ReportResponse(BaseModel):
    saved_new: bool
    exact_mail_count: int
    primary_domain: str
    domain_count: int
    domain_count_last_24h: int
    message: str



# ==========================
# BETA ACCESS PROTECTION
# ==========================
# Für die private Beta. Du kannst mehrere Codes über die Umgebungsvariable setzen:
# export NOVA_BETA_CODES="NOVA-BETA-2026,FAMILIE-TEST,FRIENDS-01"
DEFAULT_BETA_CODES = {"NOVA-BETA-2026"}

def get_allowed_beta_codes():
    raw_codes = os.getenv("NOVA_BETA_CODES", "")
    codes = {code.strip() for code in raw_codes.split(",") if code.strip()}
    return codes or DEFAULT_BETA_CODES

def validate_beta_code(beta_code: Optional[str]):
    clean_code = clean_text(beta_code).strip()
    if not clean_code or clean_code not in get_allowed_beta_codes():
        raise HTTPException(status_code=403, detail="Ungültiger oder fehlender Beta-Code.")
    return True

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT,
            domain TEXT,
            links TEXT,
            risk_score INTEGER,
            bewertung TEXT,
            risiken TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            domain TEXT,
            created_at TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id)
        )
    """)

    cursor.execute("PRAGMA table_info(reports)")
    columns = [col[1] for col in cursor.fetchall()]
    if "report_count" not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN report_count INTEGER DEFAULT 1")

    conn.commit()
    conn.close()


init_db()


def clean_text(value):
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\x00", "")
    text = text.replace("\ufffd", "")
    text = text.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
    return text.strip()


def generate_email_hash(email_text: str):
    normalized_text = email_text.strip().lower()
    return hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()


def extract_links(email_text: str):
    return re.findall(r'https?://[^\s<>"\'()]+', email_text)


def extract_domains(email_text: str):
    links = extract_links(email_text)
    domains = []

    for link in links:
        parsed = urlparse(link)
        domain = parsed.netloc.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        if domain and domain not in domains:
            domains.append(domain)

    return domains


def get_primary_domain(email_text: str):
    domains = extract_domains(email_text)
    return domains[0] if domains else ""


def get_domain_count(domain: str):
    if not domain or not domain.strip():
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM report_domains WHERE domain = ?", (domain.strip().lower(),))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_domain_count_last_24h(domain: str):
    if not domain or not domain.strip():
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*)
        FROM report_domains
        WHERE domain = ?
          AND datetime(created_at) >= datetime('now', '-1 day')
    """, (domain.strip().lower(),))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_email_report_count(hash_value: str):
    if not hash_value:
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COALESCE(report_count, 1) FROM reports WHERE hash = ?", (hash_value,))
    row = cursor.fetchone()
    conn.close()
    return int(row[0]) if row else 0


def save_report(hash_value, domain, links, risk_score, bewertung, risiken, domains_list=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM reports WHERE hash = ?", (hash_value,))
    existing = cursor.fetchone()

    if existing:
        report_id = existing[0]
        cursor.execute("""
            UPDATE reports
            SET report_count = COALESCE(report_count, 1) + 1
            WHERE id = ?
        """, (report_id,))

        if domains_list:
            for single_domain in domains_list:
                clean_domain = single_domain.strip().lower()
                if clean_domain:
                    cursor.execute("""
                        INSERT INTO report_domains (report_id, domain, created_at)
                        VALUES (?, ?, datetime('now'))
                    """, (report_id, clean_domain))

        conn.commit()
        conn.close()
        return False

    cursor.execute("""
        INSERT INTO reports (hash, domain, links, risk_score, bewertung, risiken, report_count, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'))
    """, (hash_value, domain, links, risk_score, bewertung, risiken))

    report_id = cursor.lastrowid

    if domains_list:
        for single_domain in domains_list:
            clean_domain = single_domain.strip().lower()
            if clean_domain:
                cursor.execute("""
                    INSERT INTO report_domains (report_id, domain, created_at)
                    VALUES (?, ?, datetime('now'))
                """, (report_id, clean_domain))

    conn.commit()
    conn.close()
    return True


def get_risk_label(score: int):
    if score < 30:
        return "Sicher"
    if score < 70:
        return "Vorsicht"
    return "Phishing"


def get_risk_level(score: int):
    if score <= 9:
        return "Sehr niedrig"
    if score <= 29:
        return "Niedrig"
    if score <= 49:
        return "Mittel"
    if score <= 69:
        return "Erhöht"
    if score <= 84:
        return "Hoch"
    return "Sehr hoch"


def get_recommendation(label: str):
    if label == "Phishing":
        return "Nicht klicken, keine Daten eingeben, keine Anhänge öffnen und die E-Mail idealerweise löschen oder intern melden."
    if label == "Vorsicht":
        return "Absender, Links, Anhänge und Kontext genau prüfen. Erst nach Verifikation handeln."
    return "Aktuell ist keine direkte Aktion erforderlich. Bei Unsicherheit trotzdem Absender und Kontext kurz prüfen."


def map_risks(risks: list[str]):
    mapped = []
    mapping = {
        "dringlichkeit": "🔴 DRUCK",
        "zeitdruck": "🔴 DRUCK",
        "sofort": "🔴 DRUCK",
        "login": "🔴 LOGIN-ANFRAGE",
        "passwort": "🔴 LOGIN-ANFRAGE",
        "anmelden": "🔴 LOGIN-ANFRAGE",
        "link": "🔴 VERDÄCHTIGER LINK",
        "url": "🔴 VERDÄCHTIGER LINK",
        "zahlung": "🔴 ZAHLUNGSAUFFORDERUNG",
        "rechnung": "🟠 RECHNUNG / ZAHLUNG",
        "überweisung": "🔴 ZAHLUNGSAUFFORDERUNG",
        "bank": "🟠 BANK / KONTODATEN",
        "konto": "🟠 BANK / KONTODATEN",
        "anhang": "🟠 VERDÄCHTIGER ANHANG",
        "datei": "🟠 VERDÄCHTIGER ANHANG",
        "drohung": "🔴 DROHUNG",
        "sperrung": "🔴 DROHUNG / SPERRUNG",
        "verifizierung": "🟠 IDENTITÄT BESTÄTIGEN",
        "daten": "🟠 DATENABFRAGE",
        "absender": "🟠 ABSENDER PRÜFEN",
    }

    for risk in risks:
        risk_l = risk.lower()
        found = False
        for key, value in mapping.items():
            if key in risk_l:
                mapped.append(value)
                found = True
                break
        if not found and risk.strip():
            mapped.append(f"🟠 {risk.strip().upper()}")

    unique = []
    seen = set()
    for item in mapped:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def extract_json_block(text: str):
    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            return None
    return None


def fallback_parse_output(text: str):
    score_match = re.search(r"score\s*[:\-]?\s*\**\s*(\d{1,3})", text, re.IGNORECASE)
    if not score_match:
        score_match = re.search(r"\b(\d{1,3})\b", text)
    if not score_match:
        raise ValueError("Score konnte aus der KI-Antwort nicht gelesen werden.")

    score = max(0, min(int(score_match.group(1)), 100))
    risks = []

    risks_match = re.search(
        r"risiken\s*[:\-]?\s*(.+?)(?:begründung\s*[:\-]|reason\s*[:\-]|$)",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    if risks_match:
        risks_text = risks_match.group(1).strip()
        lines = [line.strip("•- \n\r\t") for line in risks_text.splitlines() if line.strip()]
        if len(lines) > 1:
            risks = lines
        else:
            risks = [r.strip("•- \n\r\t") for r in risks_text.split(",") if r.strip()]

    reason_match = re.search(r"(?:begründung|reason)\s*[:\-]?\s*(.+)$", text, re.IGNORECASE | re.DOTALL)
    reason = reason_match.group(1).strip() if reason_match else "Keine Begründung verfügbar."

    return {"score": score, "risks": risks, "reason": reason}


def extract_response_text(response):
    try:
        if getattr(response, "output_text", None):
            return response.output_text.strip()
    except Exception:
        pass

    output_parts = []
    try:
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) == "message":
                for content in getattr(item, "content", []) or []:
                    text_value = getattr(content, "text", None)
                    if text_value:
                        output_parts.append(text_value)
    except Exception:
        pass

    return "\n".join(output_parts).strip()


def check_email(email_text: str):
    prompt = f"""
Du analysierst E-Mails auf Phishing-Risiken.

WICHTIGE REGELN:
- Antworte NUR als valides JSON.
- KEIN Markdown.
- KEINE ```json Blöcke.
- KEINE zusätzlichen Sätze vor oder nach dem JSON.
- "score" muss eine ganze Zahl von 0 bis 100 sein.
- "risks" muss ein JSON-Array aus kurzen Strings sein.
- "reason" muss ein kurzer erklärender Text auf Deutsch sein.
- Gib KEINE Bewertung wie "Sicher", "Vorsicht" oder "Phishing" aus.

Erlaubtes Format:
{{
  "score": 0,
  "risks": ["Dringlichkeit", "Verdächtiger Link"],
  "reason": "Kurze Begründung auf Deutsch."
}}

E-Mail:
\"\"\"
{email_text}
\"\"\"
"""

    response = client.responses.create(model="gpt-4o-mini", input=prompt)
    raw_output = extract_response_text(response)

    if not raw_output:
        raise ValueError("Die KI-Antwort war leer.")

    data = extract_json_block(raw_output)
    if data is None:
        data = fallback_parse_output(raw_output)

    score = data.get("score", 0)
    risks = data.get("risks", [])
    reason = data.get("reason", "")

    if isinstance(score, str):
        number_match = re.search(r"\d{1,3}", score)
        if not number_match:
            raise ValueError("Score konnte nicht in eine Zahl umgewandelt werden.")
        score = int(number_match.group(0))

    score = max(0, min(int(score), 100))

    if not isinstance(risks, list):
        risks = [str(risks)]

    risks = [clean_text(r) for r in risks if clean_text(r)]
    reason = clean_text(reason) if reason else "Keine Begründung verfügbar."

    return score, risks, reason


def build_analysis_response(email_text: str, score: int, risks: list[str], reason: str):
    label = get_risk_label(score)
    level = get_risk_level(score)
    recommendation = get_recommendation(label)
    mapped_risks = map_risks(risks)

    links = extract_links(email_text)
    primary_domain = get_primary_domain(email_text)
    hash_value = generate_email_hash(email_text)

    return AnalyzeResponse(
        score=score,
        label=label,
        level=level,
        risks=risks,
        mapped_risks=mapped_risks,
        reason=reason,
        recommendation=recommendation,
        primary_domain=primary_domain,
        links=links,
        domain_count=get_domain_count(primary_domain) if primary_domain else 0,
        domain_count_last_24h=get_domain_count_last_24h(primary_domain) if primary_domain else 0,
        exact_mail_count=get_email_report_count(hash_value),
    )


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "KI Phishing Checker API",
        "endpoints": ["/health", "/beta/verify", "/analyze", "/report", "/community/domain/{domain}"]
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/beta/verify")
def beta_verify(request: BetaVerifyRequest):
    validate_beta_code(request.beta_code)
    return {"status": "ok", "message": "Beta-Code gültig."}

@app.get("/community/overview")
def community_overview():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM report_domains
            WHERE datetime(created_at) >= datetime('now', '-1 day')
        """)
        reports_last_24h = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(DISTINCT domain)
            FROM report_domains
            WHERE datetime(created_at) >= datetime('now', '-1 day')
        """)
        high_risk_domains = cursor.fetchone()[0]

        conn.close()

        return {
            "reports_last_24h": reports_last_24h,
            "high_risk_domains": high_risk_domains
        }

    except Exception as e:
        return {
            "reports_last_24h": 0,
            "high_risk_domains": 0,
            "error": str(e)
        }

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(request: AnalyzeRequest):
    validate_beta_code(request.beta_code)
    email_text = clean_text(request.email_text)
    if not email_text:
        raise HTTPException(status_code=400, detail="email_text darf nicht leer sein.")

    score, risks, reason = check_email(email_text)
    return build_analysis_response(email_text, score, risks, reason)


@app.get("/community/domain/{domain}")
def community_domain(domain: str):
    clean_domain = clean_text(domain).lower().strip()

    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain darf nicht leer sein.")

    total = get_domain_count(clean_domain)
    last_24h = get_domain_count_last_24h(clean_domain)

    if total == 0:
        risk_boost = 0
        status = "unauffaellig"
        message = "Diese Domain wurde bisher nicht gemeldet."
    elif total <= 3:
        risk_boost = 5
        status = "beobachten"
        message = "Diese Domain wurde bereits vereinzelt gemeldet."
    elif total <= 10:
        risk_boost = 10
        status = "erhoeht"
        message = "Diese Domain wurde bereits mehrfach gemeldet."
    else:
        risk_boost = 15
        status = "hoch"
        message = "Diese Domain wurde häufig gemeldet. Eine Phishing-Welle ist möglich."

    return {
        "domain": clean_domain,
        "reports": total,
        "reports_last_24h": last_24h,
        "risk_boost": risk_boost,
        "status": status,
        "message": message
    }


@app.post("/report", response_model=ReportResponse)
def report_email(request: ReportRequest):
    validate_beta_code(request.beta_code)
    email_text = clean_text(request.email_text)
    if not email_text:
        raise HTTPException(status_code=400, detail="email_text darf nicht leer sein.")

    hash_value = generate_email_hash(email_text)
    domains_list = extract_domains(email_text)
    primary_domain = get_primary_domain(email_text)
    links = extract_links(email_text)

    saved_new = save_report(
        hash_value=hash_value,
        domain=", ".join(domains_list),
        links=", ".join(links),
        risk_score=request.score,
        bewertung=request.label,
        risiken=", ".join(request.mapped_risks),
        domains_list=domains_list,
    )

    exact_mail_count = get_email_report_count(hash_value)
    domain_count = get_domain_count(primary_domain) if primary_domain else 0
    domain_count_last_24h = get_domain_count_last_24h(primary_domain) if primary_domain else 0

    return ReportResponse(
        saved_new=saved_new,
        exact_mail_count=exact_mail_count,
        primary_domain=primary_domain,
        domain_count=domain_count,
        domain_count_last_24h=domain_count_last_24h,
        message=(
            f"Vielen Dank für Ihre Meldung. Diese Mail wurde bisher {exact_mail_count}-mal gemeldet. "
            f"Die Domain wurde insgesamt {domain_count}-mal erfasst."
        ),
    )
