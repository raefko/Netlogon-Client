class userlog:
    def __init__(self, dc_name, computer_name, account_name, account_password,
                                                                        dc_ip):
        self.rpc = None
        self.authenticator = None
        self.dc_name = dc_name
        self.computer_name = computer_name
        self.account_name = account_name
        self.account_password = account_password
        self.dc_ip = dc_ip
        self.credential = None
        self.sessionkey = None

    def SetRPC(self, rpc):
        self.rpc = rpc

    def SetAuthenticator(self, authenticator):
        self.authenticator = authenticator

    def SetCredential(self, credential):
        self.credential = credential

    def SetSessionKey(self, sessionkey):
        self.sessionkey = sessionkey

    def UpdateAuthenticator(self, credential):
        self.authenticator["Credential"] = credential
