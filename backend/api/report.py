import io
import datetime
from flask import Blueprint, jsonify, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from backend.database.db import query
from backend.database import writer
from backend.config import ML_ENABLED

bp = Blueprint("report", __name__)

# ── Colors ────────────────────────────────────────────────────────────────────
C_DARK    = colors.HexColor("#1a1a2e")
C_ACCENT  = colors.HexColor("#16213e")
C_BLUE    = colors.HexColor("#0f3460")
C_TEAL    = colors.HexColor("#00b4d8")
C_GREEN   = colors.HexColor("#06d6a0")
C_RED     = colors.HexColor("#ef476f")
C_GRAY    = colors.HexColor("#6b7280")
C_LGRAY   = colors.HexColor("#f3f4f6")
C_WHITE   = colors.white
C_ROW_A   = colors.HexColor("#f9fafb")
C_ROW_B   = colors.white
C_BORDER  = colors.HexColor("#e5e7eb")


@bp.get("/api/history_dates")
def history_dates():
    dates = writer.get_history_dates()
    return jsonify({"dates": dates})


def _validate_dates(body: dict) -> tuple[str, str, str | None]:
    today     = datetime.date.today()
    client_today_str = body.get("client_today", "")
    if client_today_str:
        try:
            today = datetime.date.fromisoformat(client_today_str)
        except ValueError:
            pass
    start_str = body.get("start_date", "")
    end_str   = body.get("end_date", "")
    try:
        start_dt = datetime.date.fromisoformat(start_str)
        end_dt   = datetime.date.fromisoformat(end_str)
    except ValueError:
        return None, None, "Invalid date format. Use YYYY-MM-DD."
    if end_dt < start_dt:
        return None, None, "End date must be >= start date."
    if end_dt > today:
        return None, None, "End date cannot be in the future."
    return start_str, end_str, None


@bp.post("/api/report")
def generate_report():
    body                    = request.get_json(silent=True) or {}
    start_str, end_str, err = _validate_dates(body)
    if err:
        return jsonify({"error": err}), 400

    start_sql = f"{start_str} 00:00:00"
    end_sql   = f"{end_str} 23:59:59"

    rows = query("""
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events
        WHERE timestamp >= ? AND timestamp <= ?
        UNION ALL
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events_archive
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC
    """, (start_sql, end_sql, start_sql, end_sql))

    if not rows and ML_ENABLED:
        return jsonify({"error": "No data found for the selected date range."}), 404

    # --- ML OFF — generate report with only system/controller metrics ---
    if not ML_ENABLED:
        rows = []

    pdf_bytes = _build_pdf(start_str, end_str, rows)
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    filename = f"ddos_report_{start_str}_to_{end_str}.pdf"
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_header(text: str, styles) -> list:
    style = ParagraphStyle("sec", parent=styles["Normal"],
                           fontSize=12, fontName="Helvetica-Bold",
                           textColor=C_DARK,
                           spaceBefore=14, spaceAfter=2,
                           leftPadding=0)
    return [
        Paragraph(text, style),
        HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceAfter=4),
        Spacer(1, 0.15*cm),
    ]


def _metric_table(data: list, col_widths: list) -> Table:
    tbl = Table(data, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 1), (-1, -1), "CENTER"),
    ]))
    return tbl


def _build_pdf(start_str: str, end_str: str, rows: list[dict]) -> bytes:
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    normal_sm = ParagraphStyle("nsm", parent=styles["Normal"], fontSize=8.5)
    bold_sm   = ParagraphStyle("bsm", parent=styles["Normal"],
                               fontSize=8.5, fontName="Helvetica-Bold")

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("A-DDoS Mitigation System",
        ParagraphStyle("cover_sub", parent=styles["Normal"],
                       fontSize=11, textColor=C_GRAY, alignment=1)))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("DDoS Incident Report",
        ParagraphStyle("cover_title", parent=styles["Title"],
                       fontSize=22, textColor=C_DARK, alignment=1, spaceAfter=4)))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL))
    story.append(Spacer(1, 0.3*cm))

    gen_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_data = [
        ["Report Period", f"{start_str} - {end_str}"],
        ["Generated At",  gen_ts],
        ["Classification", "ML: Isolation Forest + Random Forest"],
    ]
    meta_tbl = Table(meta_data, colWidths=[5*cm, 11*cm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), C_GRAY),
        ("TOPPADDING",    (0,0),(-1,-1), 3),
        ("BOTTOMPADDING", (0,0),(-1,-1), 3),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.4*cm))

    # ── Deduplicate ───────────────────────────────────────────────────────────
    seen: set = set()
    deduped = []
    for r in rows:
        key = (r["src_ip"], r["action_taken"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    total_threats = len(deduped)
    vectors: dict[str, int] = {}
    actions: dict[str, int] = {}
    for r in deduped:
        v = r["attack_vector"] or "Uncertain"
        a = r["action_taken"]  or "-"
        vectors[v] = vectors.get(v, 0) + 1
        actions[a] = actions.get(a, 0) + 1

    manual_release = sum(1 for r in deduped if r["is_manual"] and "Release" in str(r["action_taken"]))
    manual_block   = sum(1 for r in deduped if r["is_manual"] and "Block"   in str(r["action_taken"]))

    summary_rows = query("""
        SELECT SUM(total_flows_observed) AS total_flows,
               SUM(true_negatives_passed) AS true_neg,
               SUM(false_positives) AS fp
        FROM traffic_summary
        WHERE timestamp >= ? AND timestamp <= ?
    """, (f"{start_str} 00:00:00", f"{end_str} 23:59:59"))
    sr        = summary_rows[0] if summary_rows else {}
    tot_flows = sr.get("total_flows") or 0
    true_neg  = sr.get("true_neg")    or 0
    fp_count  = sr.get("fp")          or 0

    # Get packet-level metrics from global_counters
    pkt_rows = query("SELECT total_packets, malicious_dropped FROM global_counters WHERE id = 1")
    pkt_row  = pkt_rows[0] if pkt_rows else {}
    tot_packets     = pkt_row.get("total_packets") or 0
    malicious_pkts  = pkt_row.get("malicious_dropped") or 0

    if_m    = writer.get_if_metrics(start_str, end_str)
    fp_rate = if_m.get("fpr", 0)

    # ── Section 1: Executive Summary ─────────────────────────────────────────
    story += _section_header("1.  Executive Summary", styles)

    high_count = sum(1 for r in deduped if (r.get("priority") or "").lower() == "high")
    low_count  = total_threats - high_count

    sum_left = [
        ["Metric", "Value"],
        ["Report Period",           f"{start_str} - {end_str}"],
        ["Total Threats Mitigated", str(total_threats)],
        ["High Priority",           str(high_count)],
        ["Low Priority",            str(low_count)],
        ["Manual Releases",         str(manual_release)],
        ["Manual Blocks",           str(manual_block)],
        ["", ""],
        ["ML Metrics",  "Value"],
        ["False Positives",         str(fp_count)],
        ["FP Rate",                 f"{fp_rate:.2f}%"],
        ["IF Precision",            f"{if_m.get('precision',0):.2f}%"],
        ["IF Recall",               f"{if_m.get('recall',0):.2f}%"],
        ["IF F1-Score",             f"{if_m.get('f1',0):.2f}%"],
        ["IF Accuracy",             f"{if_m.get('accuracy',0):.2f}%"],
        ["", ""],
        ["", ""],

    ]
    sum_right = [
        ["Traffic Summary", "Count"],
        ["Total Flows Observed",    str(tot_flows)],
        ["Total Packets Analyzed",  str(tot_packets)],
        ["Malicious Packets",       str(malicious_pkts)],
        ["True Negatives Passed",   str(true_neg)],
        ["", ""],
        ["Attack Vector", "Count"],
        ["ICMP Flood",  str(vectors.get("ICMP Flood", 0))],
        ["SYN Flood",   str(vectors.get("SYN Flood",  0))],
        ["UDP Flood",   str(vectors.get("UDP Flood",  0))],
        ["Uncertain",   str(vectors.get("Uncertain",  0))],
        ["", ""],
        ["Action",      "Count"],
        ["Quarantined", str(actions.get("Quarantined", 0))],
        ["Time Ban",    str(actions.get("Time Ban",    0))],
        ["Blackhole",   str(actions.get("Blackhole",   0))],
        ["Released",    str(actions.get("Released",    0))],
    ]

    def _kv_table(data, col_widths, section_rows=None):
        """Create a styled table with optional blue sub-header rows."""
        t = Table(data, colWidths=col_widths)
        style_cmds = [
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTNAME",      (0, 1), (0, -1),  "Helvetica-Bold"),
            ("TEXTCOLOR",     (0, 1), (0, -1),  C_GRAY),
        ]
        # Style sub-header rows with blue background
        if section_rows:
            for row_idx in section_rows:
                style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), C_ACCENT))
                style_cmds.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), C_WHITE))
                style_cmds.append(("FONTNAME", (0, row_idx), (-1, row_idx), "Helvetica-Bold"))
        t.setStyle(TableStyle(style_cmds))
        return t

    # Inner-table widths sum to match their outer container cells (8.7cm/8.0cm),
    # and the value column (4.2cm) fits the longest real value.
    side_by_side = Table([[_kv_table(sum_left,  [4.5*cm, 4.2*cm], section_rows=[8]),
                            Spacer(0.3*cm, 1),
                            _kv_table(sum_right, [5.0*cm, 3.0*cm], section_rows=[0, 6, 12])]],
                         colWidths=[8.7*cm, 0.3*cm, 8*cm])
    # The outer wrapper's cell padding is zeroed so the inner tables keep the
    # full width allocated to them and do not overflow their cells.
    side_by_side.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(side_by_side)
    story.append(Spacer(1, 0.6*cm))

    # ── Page break before Performance Benchmark ────────────────────────────────
    from reportlab.platypus import PageBreak
    story.append(PageBreak())

    # ── Section 2: Performance Benchmark ─────────────────────────────────────
    story += _section_header("2.  Performance Benchmark", styles)

    rf_m  = writer.get_rf_metrics(start_str, end_str)
    sys   = writer.get_system_metrics_attack_vs_baseline(start_str, end_str)
    lat_m = writer.get_latency_metrics(start_str, end_str)

    def _bench_table(data):
        desc_style = ParagraphStyle(
            "bench_desc", fontName="Helvetica", fontSize=8.5,
            leading=11, textColor=C_DARK
        )
        # Wrap column 2 (Description) in Paragraph so long strings
        # line-wrap inside the cell instead of overflowing the column.
        # Plain strings in reportlab never wrap regardless of column width.
        wrapped = []
        for i, row in enumerate(data):
            if len(row) >= 3 and i > 0:
                wrapped.append([row[0], row[1], Paragraph(str(row[2]), desc_style)])
            else:
                wrapped.append(row)
        tbl = Table(wrapped, colWidths=[5.5*cm, 2.5*cm, 9.0*cm], repeatRows=1)
        style = [
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 1), (1, -1),  "CENTER"),
            ("FONTNAME",      (1, 1), (1, -1),  "Helvetica-Bold"),
            ("TEXTCOLOR",     (1, 1), (1, -1),  C_BLUE),
        ]
        tbl.setStyle(TableStyle(style))
        return tbl

    # ── 2a: Isolation Forest ──────────────────────────────────────────────────
    story.append(Paragraph("2a.  Isolation Forest-Anomaly Detection",
        ParagraphStyle("sub", parent=styles["Normal"],
                       fontSize=10, fontName="Helvetica-Bold",
                       textColor=C_DARK, spaceBefore=6, spaceAfter=4)))

    if_data = [
        ["Metric", "Value", "Description"],
        ["Precision",                f"{if_m.get('precision',0):.2f}%",  "Share of flagged anomalies that were genuine attacks"],
        ["Recall (TPR)",             f"{if_m.get('recall',0):.2f}%",     "Share of actual attacks successfully flagged"],
        ["F1-Score",                 f"{if_m.get('f1',0):.2f}%",         "Balanced measure combining Precision and Recall"],
        ["Accuracy",                 f"{if_m.get('accuracy',0):.2f}%",   "Overall proportion of correct anomaly decisions"],
        ["False Positive Rate (FPR)",f"{if_m.get('fpr',0):.2f}%",        "Normal traffic incorrectly flagged as an attack"],
        ["False Negative Rate (FNR)",f"{if_m.get('fnr',0):.2f}%",        "Actual attacks that went undetected"],
        ["True Positive Rate (TPR)", f"{if_m.get('tpr',0):.2f}%",        "Same measure as Recall, attacks correctly flagged"],
        ["True Negative Rate (TNR)", f"{if_m.get('tnr',0):.2f}%",        "Normal traffic correctly identified as safe"],
    ]
    story.append(_bench_table(if_data))
    story.append(Spacer(1, 0.3*cm))

    # IF 2x2 Confusion Matrix
    _tp = if_m.get('tp', 0); _fp = if_m.get('fp', 0)
    _tn = if_m.get('tn', 0); _fn = if_m.get('fn', 0)
    _lbl_if = ParagraphStyle("cml", parent=styles["Normal"], fontSize=7.5, alignment=1, textColor=C_GRAY)

    def _if_cell(label, val, color):
        return Paragraph(f"{label}\n{val}", ParagraphStyle("ifc", parent=styles["Normal"],
            fontSize=13, fontName="Helvetica-Bold", alignment=1, textColor=color))

    if_cm_data = [
        ["", Paragraph("Predicted: Attack", _lbl_if), Paragraph("Predicted: Normal", _lbl_if)],
        [Paragraph("Actual: Attack", _lbl_if), _if_cell("TP", _tp, C_GREEN), _if_cell("FN", _fn, C_RED)],
        [Paragraph("Actual: Normal", _lbl_if), _if_cell("FP", _fp, C_RED),  _if_cell("TN", _tn, C_GREEN)],
    ]
    if_cm_tbl = Table(if_cm_data, colWidths=[3.5*cm, 4.5*cm, 4.5*cm])
    if_cm_tbl.setStyle(TableStyle([
        ("BACKGROUND", (1,1),(1,1), colors.HexColor("#e6fff5")),
        ("BACKGROUND", (2,2),(2,2), colors.HexColor("#e6fff5")),
        ("BACKGROUND", (2,1),(2,1), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (1,2),(1,2), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (0,0),(0,-1), C_LGRAY),
        ("BACKGROUND", (1,0),(-1,0), C_LGRAY),
        ("GRID",       (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ("VALIGN",  (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",   (0,0),(-1,-1), "CENTER"),
    ]))
    if_cm_wrap = Table([[if_cm_tbl]], colWidths=[17.0*cm])
    if_cm_wrap.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")]))
    story.append(if_cm_wrap)
    story.append(Spacer(1, 0.4*cm))

    # ── 2b: Random Forest ─────────────────────────────────────────────────────
    story.append(Paragraph("2b.  Random Forest-Attack Classification",
        ParagraphStyle("sub2", parent=styles["Normal"],
                       fontSize=10, fontName="Helvetica-Bold",
                       textColor=C_DARK, spaceBefore=6, spaceAfter=4)))

    rf_o    = rf_m.get("overall",   {})
    rf_conf = rf_m.get("confusion", {})

    rf_data = [
        ["Metric", "Value", "Description"],
        ["Precision",  f"{rf_o.get('precision',0):.2f}%", "Share of classified flows assigned the correct attack type"],
        ["Recall",     f"{rf_o.get('recall',0):.2f}%",    "Share of attacks of each type that were correctly identified"],
        ["F1-Score",   f"{rf_o.get('f1',0):.2f}%",        "Balanced measure combining Precision and Recall"],
        ["Accuracy",   f"{rf_o.get('accuracy',0):.2f}%",  "Overall proportion of correct classifications"],
    ]
    rf_tbl = Table(rf_data, colWidths=[5.5*cm, 2.5*cm, 9.0*cm], repeatRows=1)
    rf_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 1), (1, -1),  "CENTER"),
        ("FONTNAME",      (1, 1), (1, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",     (1, 1), (1, -1),  C_BLUE),
    ]))
    story.append(rf_tbl)
    story.append(Spacer(1, 0.3*cm))

    # RF 3x3 Confusion Matrix
    _lbl = ParagraphStyle("rfl", parent=styles["Normal"], fontSize=7.5, alignment=1, textColor=C_GRAY)

    def _cm_cell(val, is_diag):
        c = C_GREEN if is_diag else C_RED
        return Paragraph(str(val), ParagraphStyle("rfc", parent=styles["Normal"],
            fontSize=13, fontName="Helvetica-Bold", alignment=1, textColor=c))

    rf_cm_data = [
        ["", Paragraph("Predicted: SYN", _lbl), Paragraph("Predicted: ICMP", _lbl), Paragraph("Predicted: UDP", _lbl)],
        [Paragraph("Act: SYN",  _lbl),
         _cm_cell(rf_conf.get("syn_as_syn",   0), True),
         _cm_cell(rf_conf.get("syn_as_icmp",  0), False),
         _cm_cell(rf_conf.get("syn_as_udp",   0), False)],
        [Paragraph("Act: ICMP", _lbl),
         _cm_cell(rf_conf.get("icmp_as_syn",  0), False),
         _cm_cell(rf_conf.get("icmp_as_icmp", 0), True),
         _cm_cell(rf_conf.get("icmp_as_udp",  0), False)],
        [Paragraph("Act: UDP",  _lbl),
         _cm_cell(rf_conf.get("udp_as_syn",   0), False),
         _cm_cell(rf_conf.get("udp_as_icmp",  0), False),
         _cm_cell(rf_conf.get("udp_as_udp",   0), True)],
    ]
    rf_cm_tbl = Table(rf_cm_data, colWidths=[3.5*cm, 4.5*cm, 4.5*cm, 4.5*cm])
    rf_cm_tbl.setStyle(TableStyle([
        ("BACKGROUND", (1,1),(1,1), colors.HexColor("#e6fff5")),
        ("BACKGROUND", (2,2),(2,2), colors.HexColor("#e6fff5")),
        ("BACKGROUND", (3,3),(3,3), colors.HexColor("#e6fff5")),
        ("BACKGROUND", (2,1),(2,1), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (3,1),(3,1), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (1,2),(1,2), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (3,2),(3,2), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (1,3),(1,3), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (2,3),(2,3), colors.HexColor("#fff0f3")),
        ("BACKGROUND", (0,0),(0,-1), C_LGRAY),
        ("BACKGROUND", (1,0),(-1,0), C_LGRAY),
        ("GRID",       (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ("VALIGN",  (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",   (0,0),(-1,-1), "CENTER"),
    ]))
    rf_cm_wrap = Table([[rf_cm_tbl]], colWidths=[17.0*cm])
    rf_cm_wrap.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")]))
    story.append(rf_cm_wrap)
    story.append(Spacer(1, 0.4*cm))

    # ── 2c: Response Latency ──────────────────────────────────────────────────
    story.append(Paragraph("2c.  Response Latency",
        ParagraphStyle("sub3a", parent=styles["Normal"],
                       fontSize=10, fontName="Helvetica-Bold",
                       textColor=C_DARK, spaceBefore=6, spaceAfter=4)))

    # Helper: show N/A when ML is OFF or value is zero (no data collected)
    def _ms(val):
        if not ML_ENABLED or val == 0:
            return "N/A"
        return f"{val:.1f} ms"

    def _cpu(val):
        if not ML_ENABLED:
            return "N/A"
        return f"{val:.2f}%"

    lat_data = [
        ["Metric", "Value", "Description"],
        ["Detection Time",           _ms(lat_m.get("detection_ms", 0)),
         "Average time taken to detect an attack"],
        ["Mitigation Response Time", _ms(lat_m.get("mitigation_ms", 0)),
         "Interval between the anomaly flag and the FlowMod blocking rule install"],
    ]
    story.append(_bench_table(lat_data))
    story.append(Spacer(1, 0.4*cm))

    # ── 2d: Controller Resource Overhead ───────────────────────────────────────
    story.append(Paragraph("2d.  Controller Resource Overhead",
        ParagraphStyle("sub3", parent=styles["Normal"],
                       fontSize=10, fontName="Helvetica-Bold",
                       textColor=C_DARK, spaceBefore=6, spaceAfter=4)))

    res_data = [
        ["Metric", "Value", "Description"],
        ["Controller CPU (Baseline)",      f"{sys.get('baseline_ctrl_cpu',0):.2f}%",
         "Ryu controller CPU usage under normal traffic"],
        ["Controller CPU (Active Attack)", f"{sys.get('attack_ctrl_cpu',0):.2f}%",
         "Ryu controller average CPU usage during a DDoS simulation"],
        ["Controller CPU (Mitigation)",    _cpu(sys.get("mitigation_ctrl_cpu", 0)),
         "Ryu controller CPU usage during simultaneous detection and mitigation"],
    ]
    story.append(_bench_table(res_data))
    story.append(Spacer(1, 0.6*cm))

    # ── Section 3: Offences Summary ───────────────────────────────────────────
    story += _section_header("3.  Offences Summary", styles)

    off_rows = query("""
        SELECT src_ip,
               COUNT(*)            AS sessions,
               MAX(offence_count)  AS max_offences,
               MAX(ban_level)      AS max_ban,
               MAX(phase_reached)  AS max_phase,
               MIN(first_seen)     AS first_seen,
               MAX(unblocked_at)   AS last_seen,
               attack_vector
        FROM ip_attack_history
        WHERE date(unblocked_at) >= ? AND date(unblocked_at) <= ?
        GROUP BY src_ip
        ORDER BY max_offences DESC, sessions DESC
    """, (start_str, end_str))

    if off_rows:
        off_headers = ["Source IP", "Sessions", "Max Offences", "First Seen", "Last Seen"]
        off_data = [off_headers]
        for r in off_rows:
            off_data.append([
                r["src_ip"],
                str(r["sessions"]),
                str(r["max_offences"] or 1),
                r["first_seen"],
                r["last_seen"],
            ])
        off_tbl = Table(off_data,
                        colWidths=[3.5*cm, 2.5*cm, 3*cm, 4.5*cm, 3.5*cm],
                        repeatRows=1)
        off_tbl.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 1), (4, -1),  "CENTER"),
            ("FONTNAME",      (0, 1), (0, -1),  "Helvetica-Bold"),
        ]))
        story.append(off_tbl)
    else:
        story.append(Paragraph("No offence history for this period.", normal_sm))

    story.append(Spacer(1, 0.6*cm))

    # ── Section 4: Chronological Mitigation Log ───────────────────────────────
    story.append(PageBreak())
    story += _section_header("4.  Chronological Mitigation Log", styles)

    log_headers = ["Timestamp", "Source IP", "Class", "Vector",
                   "Confidence", "Priority", "Action"]
    log_data = [log_headers]
    for r in deduped:
        conf_pct = f"{r['confidence']*100:.1f}%" if r["confidence"] else "-"
        log_data.append([
            r["timestamp"], r["src_ip"], r["predicted_class"],
            r["attack_vector"] or "-", conf_pct,
            r["priority"] or "-", r["action_taken"] or "-",
        ])

    log_tbl = Table(log_data,
                    colWidths=[3.6*cm, 2.6*cm, 1.7*cm, 2.3*cm, 2.3*cm, 1.7*cm, 2.8*cm],
                    repeatRows=1)
    log_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(log_tbl)
    story.append(Spacer(1, 0.6*cm))

    # ── Section 5: IP Attack History ─────────────────────────────────────────
    history_rows = query("""
        SELECT src_ip, attack_vector, if_score, confidence, priority,
               phase_reached, first_seen, unblocked_at, duration_sec,
               unblock_reason, ban_level, offence_count
        FROM ip_attack_history
        WHERE date(unblocked_at) >= ? AND date(unblocked_at) <= ?
        ORDER BY unblocked_at DESC
    """, (start_str, end_str))

    if history_rows:
        story += _section_header("5.  IP Attack History (Completed Sessions)", styles)
        # Reason column holds free-form backend text (e.g. "Manual Block
        # Escalation" measures ~3.1cm — wider than any fixed column width
        # could safely guarantee). Wrapping it in a Paragraph lets it break
        # onto a second line within its own cell instead of overflowing.
        reason_style = ParagraphStyle("reason", fontName="Helvetica", fontSize=7,
                                       leading=8.4, textColor=C_DARK)

        hist_headers = ["Source IP", "Vector", "IF Score", "Conf",
                        "Priority", "Phase", "Offences", "Duration",
                        "Unblocked At", "Reason"]
        hist_data = [hist_headers]
        for r in history_rows:
            dur     = r["duration_sec"] or 0
            dur_str = f"{dur//60}m {dur%60}s" if dur >= 60 else f"{dur}s"
            hist_data.append([
                r["src_ip"],
                r["attack_vector"] or "-",
                f"{r['if_score']:.4f}",
                f"{r['confidence']*100:.1f}%" if r["confidence"] else "-",
                r["priority"] or "-",
                f"Phase {r['phase_reached']}",
                str(r["offence_count"] or 1),
                dur_str,
                r["unblocked_at"],
                Paragraph(r["unblock_reason"] or "-", reason_style),
            ])
        hist_tbl = Table(hist_data,
                         colWidths=[1.8*cm, 1.8*cm, 1.5*cm, 1.4*cm,
                                    1.4*cm, 1.5*cm, 1.55*cm, 1.55*cm, 2.8*cm, 1.7*cm],
                         repeatRows=1)
        hist_tbl.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(hist_tbl)

    # ── Verification and Approval ─────────────────────────────────────────
    story.append(Paragraph("Verification and Approval",
        ParagraphStyle("sub6", parent=styles["Normal"],
                       fontSize=10, fontName="Helvetica-Bold",
                       textColor=C_DARK, spaceBefore=14, spaceAfter=6)))
    story.append(Paragraph(
        "I hereby verify that the findings in this incident report are "
        "accurate and that the listed mitigation actions were carried out "
        "under my supervision.",
        styles["Normal"]))
    story.append(Spacer(1, 1.6*cm))

    sig_role = Paragraph(
        '<b>Network Administrator</b>',
        ParagraphStyle("sigrole", parent=styles["Normal"], fontSize=10.5,
                       alignment=1))
    # Middle column is an empty spacer so the two rules stay separated.
    sig_data = [
        ["", "", ""],
        ["SIGNATURE OVER PRINTED NAME", "", "DATE"],
        [sig_role, "", ""],
    ]
    sig_tbl = Table(sig_data, colWidths=[7.2*cm, 1.6*cm, 6.2*cm],
                    hAlign="CENTER")
    sig_tbl.setStyle(TableStyle([
        # signing space above the rule
        ("TOPPADDING",    (0, 0), (-1, 0), 0),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 26),
        # solid rule: top edge of the caption row (left and right only)
        ("LINEABOVE",     (0, 1), (0, 1), 1, colors.black),
        ("LINEABOVE",     (2, 1), (2, 1), 1, colors.black),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, 1), 9),
        ("TOPPADDING",    (0, 1), (-1, 1), 4),
        ("TOPPADDING",    (0, 2), (-1, 2), 2),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 0),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "BOTTOM"),
    ]))
    story.append(sig_tbl)

    doc.build(story)
    return buf.getvalue()