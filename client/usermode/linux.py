from subprocess import check_call, CalledProcessError
from socket import AF_INET6

import sys
import nfqueue

IP6TABLES = "ip6tables"
RA_TYPE = "134"

def cb(payload):
    print("python callback called!")
    data = payload.get_data()
    print(data)

    accept_callback = _get_callback(data, nfqueue.NF_ACCEPT)
    reject_callback = _get_callback(data, nfqueue.NF_DROP)

    shared.new_packet(data, accept_callback, reject_callback)

    sys.stdout.flush()
    return 1

def _get_callback(payload, action):
    def callback():
        print("action called: ", action)
        payload.set_verdict(action)
    return callback

try:
    # Set ip6tables filtering rule
    check_call(["ip6tables", "-A", "INPUT", "-p", "icmpv6", "-j", "NFQUEUE",
              "--icmpv6-type", RA_TYPE, "--queue-num", RA_TYPE])

    q = nfqueue.queue()
    print("open")
    q.open()

    print("bind")
    q.bind(AF_INET6)

    print("setting callback")
    q.set_callback(cb)

    print("creating queue")
    q.create_queue(int(RA_TYPE))
    q.set_queue_maxlen(32768)

    print("trying to run")
    try:
        q.try_run()
    except KeyboardInterrupt as e:
        print("interrupted")

    print("unbind")
    q.unbind(AF_INET6)

    print("close")
    q.close()

    # Unset ip6tables filtering rule
    check_call(["ip6tables", "-D", "INPUT", "-p", "icmpv6", "-j", "NFQUEUE",
              "--icmpv6-type", RA_TYPE, "--queue-num", RA_TYPE])
except CalledProcessError:
    # TODO check for errno usage
    exit(1)
