from demon_cry_base.plugin import BasePlugin
from dc_whois.models import WhoisParams

class WhoisLookup(BasePlugin):
    name = "whois"
    description = "RDAP/WHOIS lookup for domain registration data"
    category = "network"
    parameters_model = WhoisParams
    execute_func = "dc_whois.runner:run"