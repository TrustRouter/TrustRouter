

class Shared(object):

    def new_packet(self, data, accept_callback, reject_callback):
        action = input("New RA! Do you trust it? (y/N): ")
        
        if action == "y":
            print("Accepting...")
            accept_callback()
        else:
            print("Rejecting...")
            reject_callback()
