#!/usr/bin/env python2
"""nserver lameness check script"""
# Daniel Shaw <daniel@afrinic.net>
# [ under construction ]

import sys
import pprint
import json
import getdns

DEBUG_ON = False
IPV6_YES = True
TIMEOUT_MS = 3000
SEED_RECURSORS = [{'address_data': '9.9.9.10', 'address_type': 'IPv4'}]
if IPV6_YES:
    SEED_RECURSORS.append({'address_data': '2620:fe::10', 'address_type': 'IPv6'})

def main():
    """main function"""
    if len(sys.argv) != 3:
        usage_out = {'Usage': '{0} domain.arpa nserver'.format(sys.argv[0])}
        print json.dumps(usage_out)
        sys.exit(1)

    # add check(s) here to make sure domain and nserver
    # args are the right sort of strings for what they should be
    # also need to deal with trailing '.', which currently breaks

    result = is_lame(sys.argv[1], sys.argv[2])
    print json.dumps(result)


def is_lame(domain_name, nserver_name):
    """lameness check function"""

    # prep base outut
    out = {'domain': domain_name, 'nserver': nserver_name}

    # lookup the nserver's IP address(es)
    ctx = getdns.Context()
    ctx.upstream_recursive_servers = SEED_RECURSORS
    ctx.timeout = TIMEOUT_MS

    try:
        nserver_ips = ctx.address(name=nserver_name)
    except getdns.error, err:
        print json.dumps({'error': str(err)})
        sys.exit(1)

    if nserver_ips.status == getdns.RESPSTATUS_GOOD:
        # remove AAAA responses if IPv6 flag is off
        if IPV6_YES:
            upstream_ns = nserver_ips.just_address_answers
        elif not IPV6_YES:
            answers = nserver_ips.just_address_answers
            upstream_ns = [ip for ip in answers if ip.get('address_type', '') != 'IPv6']
        else:
            print json.dumps({'error': 'WTF!'})
            sys.exit(1)

    elif nserver_ips.status == getdns.RESPSTATUS_NO_NAME:
        out['status'] = 'LAME'
        out['detail'] = 'cannot resolve nserver name (negative response)'
        return out

    elif nserver_ips.status == getdns.RESPSTATUS_ALL_TIMEOUT:
        out['status'] = 'LAME'
        out['detail'] = 'cannot resolve nserver name (query timeout)'
        return out

    else:
        print json.dumps({'error': 'WTF!'})
        sys.exit(1)

    if DEBUG_ON:
        debug_out = {'DEBUG': {'nserver': upstream_ns}}
        print json.dumps(debug_out)

    # lookup the domain's SOA...
    ctx = getdns.Context(set_from_os=0)
    ctx.resolution_type = getdns.RESOLUTION_STUB

    # ... trying each IP obtained above, in turn
    for ns_ip in upstream_ns:

        if DEBUG_ON:
            debug_out = {'DEBUG': {'query': ns_ip}}
            print json.dumps(debug_out)

        ctx.upstream_recursive_servers = [ns_ip]
        try:
            results = ctx.general(name=domain_name, request_type=getdns.RRTYPE_SOA)
        except getdns.error, err:
            print json.dumps({'error': str(err)})
            sys.exit(1)

        # and check for the AA bit set
        if results.status == getdns.RESPSTATUS_GOOD:
            if results.replies_tree[0]['answer'] and results.replies_tree[0]['header']['aa'] == 1:
                # one success is enough
                out['status'] = 'OK'
                out['detail'] = results.replies_tree[0]['answer'][0]['rdata']['serial']
                return out
            else:
                out['status'] = 'LAME'
                out['detail'] = 'no matching authoritative response'
                return out
        elif results.status == getdns.RESPSTATUS_NO_NAME:
            out['status'] = 'LAME'
            out['detail'] = 'negative response for domain SOA'
            return out
        elif results.status == getdns.RESPSTATUS_ALL_TIMEOUT:
            out['status'] = 'LAME'
            out['detail'] = 'query timeout for domain SOA'
            return out
        else:
            print json.dumps({'error': 'WTF!'})
            sys.exit(1)

    # shouldn't reach here, but if we do,
    # then we can't (necessarily) flag as lame
    out['status'] = 'UNKNOWN'
    out['detail'] = 'glitch in the matrix'
    return out


if __name__ == "__main__":
    main()
