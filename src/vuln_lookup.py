import requests

def lookup_vulnerabilities(service: str, version: str) -> list:
    """
    Query Vulners API for vulnerabilities related to a service and version.
    Returns a list of vulnerability summaries (CVE, title, URL).
    """
    if not service or not version or service == '-':
        return []
    try:
        query = f"{service} {version}"
        url = "https://vulners.com/api/v3/search/lucene/"
        params = {
            "query": query,
            "size": 3,  # Limit to top 3 results
            "type": "cve"
        }
        resp = requests.get(url, params=params, timeout=8)
        data = resp.json()
        vulns = []
        for item in data.get('data', {}).get('search', []):
            cve = item.get('id', '-')
            title = item.get('title', '-')
            href = item.get('href', '-')
            vulns.append(f"{cve}: {title} ({href})")
        return vulns
    except Exception as e:
        return [f"Error looking up vulnerabilities: {e}"]
