#!/usr/bin/env python3
from socket import AF_INET6

import sys
import nfqueue
import shared

RA_TYPE = "134"

def cb(payload):
    print("python callback called!")
    data = payload.get_data()

    accept_callback = _get_callback(payload, nfqueue.NF_ACCEPT)
    reject_callback = _get_callback(payload, nfqueue.NF_DROP)

    common_part = shared.Shared()
    common_part.new_packet(data, accept_callback, reject_callback)

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

def _get_callback(payload, action):
    def callback():
        payload.set_verdict(action)
    return callback

def _cleanup():
    print("cleanup called")

if __name__ == '__main__':
    main()
