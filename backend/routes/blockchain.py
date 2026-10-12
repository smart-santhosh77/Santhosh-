from flask import Blueprint, current_app, jsonify

blockchain_bp = Blueprint("blockchain", __name__)


@blockchain_bp.get("/config")
def blockchain_config():
    address = current_app.config["BLOCKCHAIN_REGISTRY_ADDRESS"]
    return jsonify(
        enabled=bool(address),
        registry_address=address or None,
        chain_id=current_app.config["BLOCKCHAIN_CHAIN_ID"],
    )
