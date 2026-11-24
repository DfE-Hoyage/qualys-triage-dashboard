from flask import Blueprint, jsonify, request
from services.auth import login_required
from services.vuln_service import calculate_kpis, filter_vulnerabilities, load_vulnerabilities

backend_bp = Blueprint("backend", __name__, url_prefix="/api")


@backend_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def api_vulnerabilities():
    records = load_vulnerabilities()
    filtered = filter_vulnerabilities(
        records,
        query=request.args.get("q", ""),
        qds_level=request.args.get("qds_level", ""),
        status=request.args.get("status", ""),
        service_offering=request.args.get("service_offering", ""),
        os_name=request.args.get("os", ""),
    )
    return jsonify({
        "count": len(filtered),
        "kpis": calculate_kpis(records),
        "results": filtered,
    })
