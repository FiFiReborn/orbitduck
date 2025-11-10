import socket
import json
import requests

def lookup_ip_location(target: str) -> dict:
    """Lookup IP geolocation using ip-api (no key required)."""
    try:
        ip = socket.gethostbyname(target)
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query", timeout=5)
        data = res.json()
        if data.get("status") == "success":
            return {
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "asn": data.get("as")
            }
    except Exception as e:
        return {"error": str(e)}
    return {}
