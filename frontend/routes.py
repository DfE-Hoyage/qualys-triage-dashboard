import csv
import io
from flask import Blueprint, Response, abort, redirect, render_template, request, session, url_for
from services.auth import login_required, verify_credentials
from services.vuln_service import (
    calculate_kpis,
    filter_vulnerabilities,
    get_filter_options,
    get_vulnerability_by_id,
    load_vulnerabilities,
)

frontend_bp = Blueprint("frontend", __name__)


def _sanitise_csv_cell(value: str) -> str:
    """SEC-03: Prevent CSV formula injection (=, +, -, @)."""
    text = str(value or "")
    if text and text[0] in ("=", "+", "-", "@"):
        return f"'{text}"
    return text


@frontend_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if verify_credentials(username, password):
            session["user"] = username.strip()
            return redirect(url_for("frontend.dashboard"))
        error = "Invalid credentials. Use the demo analyst account listed below."
    return render_template("login.html", error=error)


@frontend_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("frontend.login"))


@frontend_bp.route("/")
@login_required
def dashboard():
    all_records = load_vulnerabilities()
    kpis = calculate_kpis(all_records)
    options = get_filter_options(all_records)

    query = request.args.get("q", "")
    qds_level = request.args.get("qds_level", "")
    status = request.args.get("status", "")
    service_offering = request.args.get("service_offering", "")
    os_name = request.args.get("os", "")

    filtered = filter_vulnerabilities(
        all_records,
        query=query,
        qds_level=qds_level,
        status=status,
        service_offering=service_offering,
        os_name=os_name,
    )

    return render_template(
        "dashboard.html",
        vulnerabilities=filtered,
        kpis=kpis,
        options=options,
        filters={
            "q": query,
            "qds_level": qds_level,
            "status": status,
            "service_offering": service_offering,
            "os": os_name,
        },
    )


@frontend_bp.route("/vulnerability/<int:vuln_id>")
@login_required
def vulnerability_detail(vuln_id: int):
    all_records = load_vulnerabilities()
    vuln = get_vulnerability_by_id(all_records, vuln_id)
    if vuln is None:
        abort(404)
    return render_template("vuln_detail.html", vuln=vuln)


@frontend_bp.route("/export")
@login_required
def export_csv():
    all_records = load_vulnerabilities()
    filtered = filter_vulnerabilities(
        all_records,
        query=request.args.get("q", ""),
        qds_level=request.args.get("qds_level", ""),
        status=request.args.get("status", ""),
        service_offering=request.args.get("service_offering", ""),
        os_name=request.args.get("os", ""),
    )

    output = io.StringIO()
    if filtered:
        headers = [k for k in filtered[0].keys() if k not in ("id", "QDS_num", "ARS_num")]
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        for row in filtered:
            writer.writerow({h: _sanitise_csv_cell(row.get(h, "")) for h in headers})

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=qualys_filtered_export.csv"},
    )
