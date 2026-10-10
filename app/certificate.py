"""PDF certificate of custody, rendered with ReportLab."""

import io
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

MONO = ParagraphStyle("mono", fontName="Courier", fontSize=7.5, leading=9)
SMALL = ParagraphStyle("small", fontName="Helvetica", fontSize=8.5, leading=10.5)


def _p(text, style):
    # Paragraph parses a mini-markup; escape user-controlled text.
    return Paragraph(
        str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style
    )


def _describe(entry):
    d = json.loads(entry.details)
    if entry.action == "evidence.upload":
        return f"Acquired '{d.get('filename')}' ({d.get('size_bytes')} bytes); custodian {d.get('custodian')}"
    if entry.action == "custody.transfer":
        return f"Custody {d.get('from')} -> {d.get('to')}. Reason: {d.get('reason')}"
    if entry.action == "evidence.verify":
        return "Hash re-verified: " + ("MATCH" if d.get("match") else f"MISMATCH (actual {d.get('actual')})")
    if entry.action == "certificate.issue":
        return f"Certificate issued (PDF sha256 {d.get('pdf_sha256', '')[:16]}...)"
    return entry.details


def render_certificate(evidence, events, *, file_ok, actual_hash, chain, issued_by, issued_at):
    """Return PDF bytes.

    `events`: this item's audit entries; `chain`: a ChainVerification for
    the whole log; `file_ok`/`actual_hash`: result of re-hashing the file now.
    """
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title=f"Certificate of Custody - Evidence #{evidence.id}",
    )
    all_ok = file_ok and chain.ok
    story = [
        Paragraph("Certificate of Chain of Custody", styles["Title"]),
    ]
    if all_ok:
        story.append(Paragraph(
            "The integrity checks below passed at the time of issue: the stored file matches its "
            "acquisition hash and the audit log hash chain is intact.", styles["Normal"]))
    else:
        story.append(Paragraph(
            '<font color="red"><b>INTEGRITY CHECK FAILED.</b> This document does not certify '
            "custody. See the failed checks below.</font>", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    meta = [
        ["Evidence ID", str(evidence.id)],
        ["Case number", _p(evidence.case_number, SMALL)],
        ["Description", _p(evidence.description, SMALL)],
        ["Original filename", _p(evidence.original_filename, SMALL)],
        ["Size", f"{evidence.size_bytes} bytes"],
        ["Acquired by / at", _p(f"{evidence.uploaded_by.username} / {evidence.uploaded_at}", SMALL)],
        ["Current custodian", evidence.custodian.username],
        ["SHA-256 (acquisition)", _p(evidence.sha256, MONO)],
        ["SHA-256 (now)", _p(actual_hash or "FILE MISSING", MONO)],
        ["File integrity", "PASS" if file_ok else "FAIL"],
        ["Audit chain", f"PASS ({chain.entries_checked} entries)" if chain.ok else f"FAIL ({len(chain.errors)} problems)"],
        ["Audit log head hash", _p(chain.head_hash, MONO)],
        ["Issued by / at", _p(f"{issued_by} / {issued_at}", SMALL)],
    ]
    t = Table(meta, colWidths=[45 * mm, 135 * mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("TEXTCOLOR", (1, 9), (1, 10), colors.darkgreen if all_ok else colors.red),
    ]))
    story += [t, Spacer(1, 6 * mm), Paragraph("Custody events", styles["Heading2"])]

    rows = [["#", "Timestamp (UTC)", "Actor", "Event", "Entry hash"]]
    for e in events:
        rows.append([
            str(e.id),
            _p(e.timestamp[:23] + "Z", MONO),
            _p(e.actor, SMALL),
            _p(f"{e.action}: {_describe(e)}", SMALL),
            _p(e.entry_hash, MONO),
        ])
    ev_table = Table(rows, colWidths=[10 * mm, 38 * mm, 22 * mm, 68 * mm, 42 * mm], repeatRows=1)
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    story.append(ev_table)

    if not chain.ok:
        story += [Spacer(1, 4 * mm), Paragraph("Audit chain problems", styles["Heading2"])]
        for eid, msg in chain.errors:
            story.append(_p(f"entry {eid}: {msg}", styles["BodyText"]))

    story += [
        Spacer(1, 6 * mm),
        Paragraph(
            "To check this certificate later: confirm the evidence file's SHA-256 matches the value "
            "above, run <font face='Courier'>flask verify-log</font>, and confirm the audit log head "
            "hash above still appears in the log. The SHA-256 of this PDF is recorded in the "
            "certificate.issue audit entry that follows the events listed.",
            styles["Italic"],
        ),
    ]
    doc.build(story)
    return buf.getvalue()
