#!/usr/bin/env python2
"""
nserver lameness check script
RESTful API version
"""
# Daniel Shaw <daniel@afrinic.net>
# [ under construction ]

import getdns
from flask import Flask
from flask_restplus import Resource, Api


# constants to set some stuff
# (maybe move to config file in future)
IPV6_YES = True
TIMEOUT_MS = 3000
SEED_RECURSORS = [{'address_data': '9.9.9.10', 'address_type': 'IPv4'}]
if IPV6_YES:
    SEED_RECURSORS.append({'address_data': '2620:fe::10', 'address_type': 'IPv6'})


FLASK_APP = Flask(__name__)
API = Api(FLASK_APP)

@API.route('/is_lame/<string:domain>/<string:nserver>')
class IsLame(Resource):
    """Is the domain/nserver pair 'lame'?"""
    def get(self, domain, nserver):
        """Check if the given domain is 'lame' on the given nameserver."""
        return is_lame(domain, nserver)


def is_lame(domain_name, nserver_name):
    """'lameness' checking function using getdns"""

    # prep base outut
    out = {'domain': domain_name, 'nserver': nserver_name}

    # lookup the nserver's IP address(es)
    ctx = getdns.Context()
    ctx.resolution_type = getdns.RESOLUTION_STUB    # query caching resolver(s) directly
                                                    # don't waste time on full recursion
    ctx.upstream_recursive_servers = SEED_RECURSORS # optional, else get from OS (resolv.conf)
    ctx.timeout = TIMEOUT_MS

    try:
        nserver_ips = ctx.address(name=nserver_name)
    except getdns.error as err:
        return {'error': str(err)}

    if nserver_ips.status == getdns.RESPSTATUS_GOOD:
        # remove AAAA responses if IPv6 flag is off
        if IPV6_YES:
            upstream_ns = nserver_ips.just_address_answers
        elif not IPV6_YES:
            answers = nserver_ips.just_address_answers
            upstream_ns = [ip for ip in answers if ip.get('address_type', '') != 'IPv6']
        else:
            return{'error': 'WTF!'}

    elif nserver_ips.status == getdns.RESPSTATUS_NO_NAME:
        out['status'] = 'LAME'
        out['detail'] = 'cannot resolve nserver name (negative response)'
        return out

    elif nserver_ips.status == getdns.RESPSTATUS_ALL_TIMEOUT:
        out['status'] = 'LAME'
        out['detail'] = 'cannot resolve nserver name (query timeout)'
        return out

    else:
        return {'error': 'WTF!'}

    # lookup the domain's SOA...
    ctx = getdns.Context(set_from_os=0)             # we never want to use caching resolvers
    ctx.resolution_type = getdns.RESOLUTION_STUB    # nor query any root-servers here either

    # ... trying each IP obtained above, in turn
    for ns_ip in upstream_ns:

        ctx.upstream_recursive_servers = [ns_ip]
        try:
            results = ctx.general(name=domain_name, request_type=getdns.RRTYPE_SOA)
        except getdns.error as err:
            return {'error': str(err)}

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
            return {'error': 'WTF!'}

    # shouldn't reach here, but if we do,
    # then we can't (necessarily) flag as lame
    out['status'] = 'UNKNOWN'
    out['detail'] = 'glitch in the matrix'
    return out


if __name__ == "__main__":
    FLASK_APP.run()
