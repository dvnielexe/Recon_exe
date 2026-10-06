import dns.resolver

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

def lookup_record(target: str, record_type: str):
    try:
        answers = dns.resolver.resolve(target, record_type)

        return [str(answer) for answer in answers]

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.Timeout:
        return []


def scan(target: str):
    results = {}

    for record_type in RECORD_TYPES:
        results[record_type] = lookup_record(target, record_type)

    return results