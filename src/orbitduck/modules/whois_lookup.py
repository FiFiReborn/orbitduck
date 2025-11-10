import whois

def get_whois_data(domain: str) -> dict:
    """Fetch WHOIS info for a domain."""
    try:
        data = whois.whois(domain)
        return {
            "domain_name": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "country": data.country,
            "emails": data.emails
        }
    except Exception as e:
        return {"error": str(e)}
