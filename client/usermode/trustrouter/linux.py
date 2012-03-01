#!/usr/bin/env python3
from socket import AF_INET6

import sys
import nfqueue
from trustrouter.core import RAVerifier

RA_TYPE = "134"

def cb(payload):
    print("python callback called!")

    common_part = RAVerifier()
    if common_part.verify(
            payload.get_data(),
            payload.get_indev()):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        payload.set_verdict(nfqueue.NF_DROP)

    sys.stdout.flush()
    return 1

def main():
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

def _cleanup():
    print("cleanup called")

if __name__ == '__main__':
    main()
