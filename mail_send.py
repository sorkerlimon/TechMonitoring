import os
import smtplib
import ssl
from datetime import date
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

MAIL_HOST         = os.environ["MAIL_HOST"]
MAIL_PORT         = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USERNAME     = os.environ["MAIL_USERNAME"]
MAIL_PASSWORD     = os.environ["MAIL_PASSWORD"]
MAIL_FROM_ADDRESS = os.environ["MAIL_FROM_ADDRESS"]
MAIL_FROM_NAME    = os.environ.get("MAIL_FROM_NAME", "Support AuthPay")

def weekly_report_subject(on_date: date | None = None) -> str:
    report_date = on_date or date.today()
    return f"Weekly Monitoring Report ({report_date.year}-{report_date.month}-{report_date.day})"


def build_pdf_attachment(pdf_path: str) -> MIMEApplication:
    path = Path(pdf_path)
    if not path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    if path.suffix.lower() != ".pdf":
        raise ValueError(f"Expected a .pdf file, got: {path.suffix}")
    with open(path, "rb") as f:
        part = MIMEApplication(f.read(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=path.name)
    return part


def build_message(to_emails: str | list[str], subject: str, pdf_path: str | None = None) -> MIMEMultipart:
    if isinstance(to_emails, list):
        recipients = [e.strip() for e in to_emails if (e or "").strip()]
    else:
        recipients = [e.strip() for e in str(to_emails).replace(";", ",").replace("\n", ",").split(",") if e.strip()]
    if not recipients:
        raise ValueError("recipient email is required")

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"]    = f"{MAIL_FROM_NAME} <{MAIL_FROM_ADDRESS}>"
    msg["To"]      = ", ".join(recipients)
    if pdf_path:
        msg.attach(build_pdf_attachment(pdf_path))
    return msg, recipients


def send_email(to_emails: str | list[str], subject: str | None = None, pdf_path: str | None = None) -> None:
    message, recipients = build_message(to_emails, subject or weekly_report_subject(), pdf_path)
    context = ssl.create_default_context()
    if MAIL_PORT == 465:
        server_cls = smtplib.SMTP_SSL
        connect_kwargs = {"context": context}
    else:
        server_cls = smtplib.SMTP
        connect_kwargs = {}
    with server_cls(MAIL_HOST, MAIL_PORT, **connect_kwargs) as server:
        if MAIL_PORT != 465:
            server.starttls(context=context)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM_ADDRESS, recipients, message.as_string())
    print(f"✅ Email sent successfully to {', '.join(recipients)}")


if __name__ == "__main__":
    send_email(
        "limon@technobd.com",
        pdf_path="data/weekly_uptime.pdf",
    )