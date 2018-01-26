#!/usr/bin/env python2
"""nserver lameness check script"""
# Daniel Shaw <daniel@afrinic.net>
# [ under construction ]

import sys
#import pprint
import getdns

DEBUG_ON = False

def main():
    """main function"""
    if len(sys.argv) != 3:
        print "Usage: {0} domain.arpa nserver".format(sys.argv[0])
        sys.exit(1)

    # add check(s) here to make sure domain and nserver
    # args are the right sort of strings for what they should be
    # also need to deal with trailing ".", which currently breaks

    is_lame(sys.argv[1], sys.argv[2])


def is_lame(domain_name, nserver_name):
    """lameness check function"""

    # lookup the nserver's IP address(es)
    ip_ctx = getdns.Context(set_from_os=1)
    extensions = {"return_both_v4_and_v6" : getdns.EXTENSION_TRUE}
    ip_ctx.resolution_type = getdns.RESOLUTION_RECURSING

    try:
        nserver_ips = ip_ctx.address(name=nserver_name, extensions=extensions)
    except getdns.error, err:
        print str(err)
        sys.exit(1)

    if nserver_ips.status == getdns.RESPSTATUS_GOOD:
        upstream_ns = nserver_ips.just_address_answers
    else:
        # this needs improving - ns cant be resolved = lame too
        print "OOPS!: Address lookup of {0} failed. (Error code: {1})."\
                .format(nserver_name, nserver_ips.status)
        sys.exit(1)

    # lookup the domain SOA...
    soa_ctx = getdns.Context(set_from_os=0)
    extensions = {"return_call_reporting" : getdns.EXTENSION_TRUE}
    soa_ctx.resolution_type = getdns.RESOLUTION_STUB

    # ... trying each IP obtained above, in turn
    for ns_ip in upstream_ns:
        ns_notlame = False

        soa_ctx.upstream_recursive_servers = [ns_ip]
        try:
            results = soa_ctx.general(name=domain_name, \
                    request_type=getdns.RRTYPE_SOA, extensions=extensions)
        except getdns.error, err:
            print str(err)
            sys.exit(1)

        # and check for the AA bit set
        if results.status == getdns.RESPSTATUS_GOOD and \
                                results.replies_tree[0]['header']['aa'] == 1:
            ns_notlame = True

        # start debug (remove later)
        if DEBUG_ON:
            debug_res_out = [domain_name, results.call_reporting[0]['query_to']['address_data']]
            if ns_notlame:
                debug_res_out.append("OK")
            else:
                debug_res_out.append("LAME")
            print "DEBUG: {0} @ {1} = {2}".format(*debug_res_out)
        # end debug section

    res_out = [domain_name, nserver_name, results.call_reporting[0]['run_time/ms']]
    if ns_notlame:
        res_out.append("OK")
    else:
        res_out.append("LAME")
    print "domain: {0}, nserver: {1}, result = {3} ({2}ms)".format(*res_out)


if __name__ == "__main__":
    main()
