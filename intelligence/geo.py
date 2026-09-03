"""
Простая геолокация IP через ip-api.com (бесплатно, без ключа).
Лимит: ~45 req/min. При ошибке возвращаем None.
"""
import requests

TIMEOUT = 5


def lookup(ip: str) -> dict | None:
    """
    Возвращает dict:
        country, country_code, region, city,
        lat, lon, asn, org, isp, source
    или None при ошибке.
    """
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,countryCode,regionName,"
                          "city,lat,lon,as,org,isp,query",
            },
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()

        if data.get("status") != "success":
            return None

        asn = data.get("as") or ""
        # "AS15169 Google LLC" → asn="AS15169"
        asn_id = asn.split()[0] if asn else None

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "asn": asn_id,
            "org": data.get("org"),
            "isp": data.get("isp"),
        }
    except Exception:
        return None

if __name__ == "__main__":
    print(lookup('46.39.224.205'))