"""
VirusTotal API Integration
Looks up URLs against 70+ antivirus engines and community threat reports.
Free tier: 4 requests/minute, 500 requests/day.
"""

import os
import base64
import requests
from time import time, sleep

# ── Configuration ──
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '0e424b292b1aa750588c68ace0eaae031a1d7731b3ad9ee895bc8aa998927144')
VT_BASE_URL = 'https://www.virustotal.com/api/v3'

# ── Simple response cache (1 hour) ──
_vt_cache = {}
_VT_CACHE_TTL = 3600

# ── Rate limiting (4 requests/minute) ──
_last_request_time = 0
_MIN_REQUEST_INTERVAL = 15  # 60 sec / 4 = 15 sec minimum between requests


def _url_id(url):
    """VirusTotal uses base64-encoded URL as ID"""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def _rate_limit():
    """Ensure we don't exceed 4 requests/minute"""
    global _last_request_time
    elapsed = time() - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time()


def lookup_url(url):
    """
    Look up a URL on VirusTotal.
    Returns:
        {
            'available': True/False,
            'malicious': int,      # engines flagging as malicious
            'suspicious': int,     # engines flagging as suspicious
            'harmless': int,       # engines flagging as harmless
            'undetected': int,     # engines with no verdict
            'total_engines': int,
            'reputation': int,     # community score (-100 to +100)
            'categories': dict,    # VT classifications (phishing, malware, etc.)
            'flagged_by': list,    # names of engines that flagged it
            'verdict': str,        # 'malicious' | 'suspicious' | 'clean' | 'unknown'
            'scan_date': int,      # unix timestamp of last scan
            'vt_link': str,        # link to VT report
        }
    """
    if not VT_API_KEY:
        return {'available': False, 'error': 'No API key configured'}

    # Cache check
    cache_key = url
    if cache_key in _vt_cache:
        cached = _vt_cache[cache_key]
        if time() - cached['timestamp'] < _VT_CACHE_TTL:
            return cached['data']

    try:
        _rate_limit()

        url_id = _url_id(url)
        headers = {'x-apikey': VT_API_KEY}

        # Try GET first (existing analysis)
        response = requests.get(
            f'{VT_BASE_URL}/urls/{url_id}',
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            # URL not yet analyzed — submit for scanning
            submit_response = requests.post(
                f'{VT_BASE_URL}/urls',
                headers=headers,
                data={'url': url},
                timeout=10
            )
            if submit_response.status_code in (200, 201):
                result = {
                    'available': True,
                    'status': 'queued',
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 0,
                    'undetected': 0,
                    'total_engines': 0,
                    'reputation': 0,
                    'categories': {},
                    'flagged_by': [],
                    'verdict': 'queued',
                    'vt_link': f'https://www.virustotal.com/gui/url/{url_id}',
                }
                _vt_cache[cache_key] = {'data': result, 'timestamp': time()}
                return result
            else:
                return {'available': False, 'error': f'Submit failed: {submit_response.status_code}'}

        if response.status_code == 401:
            return {'available': False, 'error': 'Invalid API key'}
        if response.status_code == 429:
            return {'available': False, 'error': 'Rate limit exceeded'}
        if response.status_code != 200:
            return {'available': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        results = attributes.get('last_analysis_results', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        # Determine verdict
        if malicious >= 5:
            verdict = 'malicious'
        elif malicious >= 1 or suspicious >= 3:
            verdict = 'suspicious'
        elif harmless > 0:
            verdict = 'clean'
        else:
            verdict = 'unknown'

        # Collect names of engines that flagged it
        flagged_by = [
            engine_name for engine_name, result in results.items()
            if result.get('category') in ('malicious', 'suspicious')
        ][:10]  # Limit to 10

        result = {
            'available': True,
            'status': 'analyzed',
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'total_engines': total,
            'reputation': attributes.get('reputation', 0),
            'categories': attributes.get('categories', {}),
            'flagged_by': flagged_by,
            'verdict': verdict,
            'scan_date': attributes.get('last_analysis_date'),
            'vt_link': f'https://www.virustotal.com/gui/url/{url_id}',
        }

        _vt_cache[cache_key] = {'data': result, 'timestamp': time()}
        return result

    except requests.Timeout:
        return {'available': False, 'error': 'Request timeout'}
    except Exception as e:
        return {'available': False, 'error': str(e)}


def is_available():
    """Quick check if VT API is configured"""
    return bool(VT_API_KEY)


if __name__ == '__main__':
    # Test
    print("\n" + "="*70)
    print("🦠 VIRUSTOTAL API TEST")
    print("="*70 + "\n")

    test_urls = [
        'https://www.google.com',
        'https://123moviesapp.net',
        'http://testsafebrowsing.appspot.com/apiv1/phish/land.html',
        'http://testsafebrowsing.appspot.com/apiv1/phish/land.html',
    ]

    for url in test_urls:
        print(f"Checking: {url}")
        result = lookup_url(url)
        if result.get('available'):
            print(f"  Verdict: {result['verdict'].upper()}")
            print(f"  Malicious: {result['malicious']}/{result['total_engines']} engines")
            print(f"  Suspicious: {result['suspicious']}/{result['total_engines']} engines")
            print(f"  Reputation: {result['reputation']}")
            if result.get('flagged_by'):
                print(f"  Flagged by: {', '.join(result['flagged_by'][:5])}")
        else:
            print(f"  ⚠️ Not available: {result.get('error')}")
        print()