import asyncwhois
from datetime import date, datetime

from demon_cry_base.plugin import PluginConfig
from demon_cry_base.runner import PluginResult

from dc_whois.models import WhoisField, WhoisParams

CLEAN_FIELDS = (
    "domain_name",
    "created",
    "updated",
    "expires",
    "registrar",
    "registrar_url",
    "registrar_abuse_email",
    "registrar_abuse_phone",
    "name_servers",
    "status",
    "registrant_name",
    "registrant_organization",
    "registrant_email",
    "registrant_phone",
    "tech_name",
    "tech_organization",
    "tech_email",
    "tech_phone",
)


def _clean(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        parts = [_clean(v) for v in value]
        parts = [p for p in parts if p]
        return ", ".join(parts) if parts else None
    text = str(value).strip()
    return text if text else None


async def _fetch(domain: str) -> dict | None:
    try:
        result = await asyncwhois.aio_rdap_domain(domain)
        if result.parser_output:
            return result.parser_output
    except Exception:
        pass

    try:
        result = await asyncwhois.aio_whois_domain(domain)
        return result.parser_output
    except Exception:
        return None


async def run(config: PluginConfig, params: WhoisParams) -> PluginResult:
    if isinstance(config, dict):
        config = PluginConfig.model_validate(config)
    elif not isinstance(config, PluginConfig):
        config = PluginConfig.model_validate(config.model_dump())

    if isinstance(params, dict):
        params = WhoisParams.model_validate(params)
    elif not isinstance(params, WhoisParams):
        params = WhoisParams.model_validate(params.model_dump())

    _ = config
    domain = params.domain.strip().lower().rstrip(".")
    data = await _fetch(domain)
    if not data:
        return PluginResult(status="ok", entities=[])

    entities: list[WhoisField] = []
    for key in CLEAN_FIELDS:
        cleaned = _clean(data.get(key))
        if cleaned is None:
            continue
        entities.append(WhoisField(domain=domain, field=key, value=cleaned))

    return PluginResult(status="ok", entities=entities)
