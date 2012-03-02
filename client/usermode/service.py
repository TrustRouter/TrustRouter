from winservice import Service, instart

import trustrouter.windows

class TrustRouterService(Service):
    def start(self):
        self.log("TrustRouter Started")
        self.runflag = True
        self.log("TrustRouter Run")
        trustrouter.windows.run(self.log) 
    def stop(self):
        self.runflag = False
        self.log("I'm done")

instart(TrustRouterService, 'TrustRouter Service', 'Trust Router service that verifies Router Advertisments')                       
