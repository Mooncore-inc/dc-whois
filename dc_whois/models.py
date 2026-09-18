from demon_cry_base.plugin import PluginParameters
from demon_cry_base.runner import BaseEntity
from pydantic import Field


class WhoisParams(PluginParameters):
    domain: str = Field(description="Domain to lookup")


class WhoisField(BaseEntity):
    """Одно значение WHOIS: каждый ключ parser_output — отдельная сущность."""

    domain: str = Field(description="Normalized domain the value belongs to")
    field: str = Field(description="Machine-readable field name (e.g. registrar)")
    value: str = Field(description="Normalized field value")
