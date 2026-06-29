# utils/error_handler.py
# IoT Security Scanner — Graceful API Error Handler
#
# Wraps external API calls (macvendors, NVD CVE, etc.) so a network
# failure or timeout never crashes the scanner mid-scan.
#
# Usage in module2.py:
#   from utils.error_handler import safe_api_call
#   vendor = safe_api_call(get_mac_vendor, "Unknown Vendor", mac)
#
# Usage in module3.py:
#   from utils.error_handler import safe_api_call
#   cves = safe_api_call(search_cves, [], vendor_name, max_results=3)

import time
import functools


# ── Core wrapper ──────────────────────────────────────────────────────────────

def safe_api_call(func, fallback, *args, retries=1, delay=1.0, label=None, **kwargs):
    """
    Calls func(*args, **kwargs) and returns the result.
    On any exception, prints a friendly warning and returns fallback.

    Args:
        func     : the function to call (e.g. get_mac_vendor)
        fallback : value to return if all attempts fail
        *args    : positional arguments passed to func
        retries  : how many times to retry before giving up (default 1)
        delay    : seconds to wait between retries (default 1.0)
        label    : short name for logging e.g. "MAC Vendor API"
        **kwargs : keyword arguments passed to func

    Returns:
        Result of func, or fallback on failure.

    Examples:
        vendor = safe_api_call(get_mac_vendor, "Unknown Vendor", mac)
        cves   = safe_api_call(search_cves, [], vendor_name, max_results=3)
        tls    = safe_api_call(check_tls, {'supported': False,
                                            'version': 'N/A',
                                            'status': 'Not Available'}, ip)
    """
    name = label or getattr(func, '__name__', str(func))

    for attempt in range(1, retries + 2):   # retries=1 → 2 total attempts
        try:
            return func(*args, **kwargs)

        except KeyboardInterrupt:
            raise   # never swallow Ctrl+C

        except Exception as e:
            err_type = type(e).__name__

            if attempt <= retries:
                print(f"  [!] {name} failed ({err_type}) — retrying in {delay}s...")
                time.sleep(delay)
            else:
                _print_warning(name, err_type, str(e))
                return fallback

    return fallback   # unreachable but keeps linters happy


def _print_warning(name, err_type, detail):
    """Prints a consistent, non-scary warning message."""
    # Classify common errors for clearer messages
    if 'ConnectionError' in err_type or 'NewConnectionError' in detail:
        reason = 'No internet connection'
    elif 'Timeout' in err_type or 'timed out' in detail.lower():
        reason = 'Request timed out'
    elif '429' in detail or 'Too Many Requests' in detail:
        reason = 'Rate limit hit'
    elif '404' in detail or 'Not Found' in detail:
        reason = 'Not found'
    else:
        reason = f'{err_type}: {detail[:60]}'

    print(f"  [!] {name} unavailable — {reason}. Using fallback value.")


# ── Convenience decorator ─────────────────────────────────────────────────────

def with_fallback(fallback, retries=1, delay=1.0, label=None):
    """
    Decorator version of safe_api_call.
    Useful when you own the function definition.

    Example:
        @with_fallback(fallback="Unknown Vendor", retries=2, label="MAC API")
        def get_mac_vendor(mac):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return safe_api_call(
                func, fallback, *args,
                retries=retries, delay=delay,
                label=label or func.__name__,
                **kwargs
            )
        return wrapper
    return decorator


# ── Batch helper ──────────────────────────────────────────────────────────────

def safe_batch(func, items, fallback_factory, label=None, delay=0.5):
    """
    Runs func(item) for each item in a list, catching errors per-item.
    Useful for MAC vendor lookups across many devices.

    Args:
        func            : function to call per item
        items           : iterable of arguments
        fallback_factory: callable that returns a fallback for a given item
                          e.g. lambda mac: "Unknown Vendor"
        label           : name for logging
        delay           : sleep between calls (avoids rate limits)

    Returns:
        list of results, one per item (fallback on error)

    Example:
        vendors = safe_batch(
            get_mac_vendor, [d['mac'] for d in devices],
            fallback_factory=lambda _: "Unknown Vendor",
            label="MAC Vendor API",
            delay=1.0,
        )
    """
    results = []
    name    = label or getattr(func, '__name__', str(func))

    for i, item in enumerate(items):
        result = safe_api_call(func, fallback_factory(item), item, label=name)
        results.append(result)
        if i < len(items) - 1:
            time.sleep(delay)

    return results
