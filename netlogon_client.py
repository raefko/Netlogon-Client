from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from binascii import hexlify, unhexlify
from subprocess import check_call
from datetime import datetime
from struct import pack, unpack
from inspect import signature
from signal import signal, SIGINT
from sys import exit
from userlog import userlog

import hmac, hashlib, struct, sys, socket, time, itertools, uuid, binascii
import time, random, os

options = {
    0:  ["Leave the program"],
    1:  ["ComputeNetlogonCredential", nrpc.ComputeNetlogonCredential],
    2:  ["ComputeNetlogonCredentialAES", nrpc.ComputeNetlogonCredentialAES],
    3:  ["ComputeSessionKeyAES", nrpc.ComputeSessionKeyAES],
    4:  ["ComputeSessionKeyStrongKey", nrpc.ComputeSessionKeyStrongKey],
    5:  ["deriveSequenceNumber", nrpc.deriveSequenceNumber],
    6:  ["ComputeNetlogonSignatureAES", nrpc.ComputeNetlogonSignatureAES],
    7:  ["ComputeNetlogonSignatureMD5", nrpc.ComputeNetlogonSignatureMD5],
    8:  ["encryptSequenceNumberRC4", nrpc.encryptSequenceNumberRC4],
    9:  ["decryptSequenceNumberRC4", nrpc.decryptSequenceNumberRC4],
    10:  ["encryptSequenceNumberAES", nrpc.encryptSequenceNumberAES],
    11: ["decryptSequenceNumberAES", nrpc.decryptSequenceNumberAES],
    12: ["SIGN", nrpc.SIGN],
    13: ["SEAL", nrpc.SEAL],
    14: ["UNSEAL", nrpc.UNSEAL],
    15: ["getSSPType1", nrpc.getSSPType1],
    16: ["checkNullString", nrpc.checkNullString],
    17: ["hNetrServerReqChallenge", nrpc.hNetrServerReqChallenge],
    18: ["hNetrServerAuthenticate3", nrpc.hNetrServerAuthenticate3],
    19: ["hDsrGetDcNameEx2", nrpc.hDsrGetDcNameEx2],
    20: ["hDsrGetDcNameEx",nrpc.hDsrGetDcNameEx],
    21: ["hDsrGetDcName",nrpc.hDsrGetDcName],
    22: ["hNetrGetAnyDCName",nrpc.hNetrGetAnyDCName],
    23: ["hNetrGetDCName",nrpc.hNetrGetDCName],
    24: ["hDsrGetSiteName",nrpc.hDsrGetSiteName],
    25: ["hDsrGetDcSiteCoverageW",nrpc.hDsrGetDcSiteCoverageW],
    26: ["hNetrServerAuthenticate2",nrpc.hNetrServerAuthenticate2],
    27: ["hNetrServerAuthenticate",nrpc.hNetrServerAuthenticate],
    28: ["hNetrServerPasswordGet",nrpc.hNetrServerPasswordGet],
    29: ["hNetrServerTrustPasswordsGet",nrpc.hNetrServerTrustPasswordsGet],
    30: ["hNetrServerPasswordSet2",nrpc.hNetrServerPasswordSet2],
    31: ["hNetrLogonGetDomainInfo",nrpc.hNetrLogonGetDomainInfo],
    32: ["hNetrLogonGetCapabilities",nrpc.hNetrLogonGetCapabilities],
    33: ["hNetrServerGetTrustInfo",nrpc.hNetrServerGetTrustInfo]
    }
def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    sys.exit()

def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)

def ConnectRPCServer(dc_ip):
    rpc_con = None
    try :
        binding = epm.hept_map(
            dc_ip,
            nrpc.MSRPC_UUID_NRPC,
            protocol='ncacn_ip_tcp')
        rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    return rpc_con

"""
#Send a Pull Request to impacket lib to add this function in the library
def ComputeNetlogonAuthenticator(Credential, SessionKey):
    Authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    start_date = "01/01/1970 00:00:00"
    actual_date = datetime.strptime(start_date, "%d/%m/%Y %H:%M:%S")
    seconds = time.mktime(actual_date.timetuple())
    CredentialAuthenticator = nrpc.ComputeNetlogonCredentialAES(Credential,
                                                                SessionKey)
    Authenticator['Credential'] = CredentialAuthenticator
    Authenticator['Timestamp'] = seconds
    return Authenticator
"""

def Menu():
    loop = True
    while(loop):
        print("\n\n         __Netlogon_Client__")
        print("_________________________________________")
        print("\n".join([str(i) + " " + options[i][0] for i
                                                    in range(len(options))]))
        try:
            inp = int(input("Press a key... "))
            if (inp == 0):
                loop = not loop
                continue
        except:
            print("Enter a valid number... ")
        else:
            os.system("clear")
            try:
                sig = signature(options[inp][1])
            except:
                print("Enter a valid number... ")
            else:
                print("Function : " + options[inp][0])
                print("Parameters : " + str(sig))
                args = ()
                for param in list(sig.parameters):
                    inputParam = input("param... ")
                    args += (inputParam,)
                res = options[inp][1](*args)
                print(res)
                input()

def authenticate(rpc_con, user):
    Client_Challenge = bytes(random.getrandbits(8) for i in range(8))
    status = nrpc.hNetrServerReqChallenge(
        rpc_con,
        NULL,
        user.computer_name + '\x00',
        Client_Challenge)
    if (status == None or status['ErrorCode'] != 0):
        fail(f'Error NetrServerReqChallenge')
    else:
        #status.dump()
        Server_Challenge = status['ServerChallenge']
        print("Client_Challenge : ", Client_Challenge)
        print("Server_Challenge : ", Server_Challenge)
    SessionKey = nrpc.ComputeSessionKeyAES(
        user.account_password,
        Client_Challenge,
        Server_Challenge,
        bytearray.fromhex(user.account_password))
    print("Session_Key : ", SessionKey)
    Credential = nrpc.ComputeNetlogonCredentialAES(Client_Challenge, SessionKey)
    print("Credential : ", Credential)
    negotiateFlags = 0x612fffff
    try:
        resp = nrpc.hNetrServerAuthenticate3(
            rpc_con, user.dc_name + '\x00',
            user.account_name  + '\x00',
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            user.computer_name + '\x00', Credential, negotiateFlags)
        Authenticator = nrpc.ComputeNetlogonAuthenticator(
            Credential,
            SessionKey)
        resp = nrpc.hNetrLogonGetCapabilities(
            rpc_con,
            user.dc_name,
            user.computer_name,
            Authenticator)
        print("Secure Channel is UP !")
        Menu()
    except Exception as e:
        fail(f'Unexpected error code from DC: {e}.')

def InitiateSecureChannel(user):
    rpc_con = ConnectRPCServer(user.dc_ip)
    try :
        authenticate(rpc_con, user)
    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error.
        if ex.get_error_code() == 0xc0000022:
            pass
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')
        sys.exit(0)


def main():
    if (len(sys.argv) != 5):
        print('Usage: netlogon_client.py <dc-name> <account_name> \
                <account_password_hash> <dc-ip>\n')
        print('Note: dc-name should be the (NetBIOS) computer name  \
                of the domain controller.')
        sys.exit(1)
    else:
        signal(SIGINT, handler)
        print("\n\n         __Starting Client__")
        [_, dc_name, account_name, account_password, dc_ip] = sys.argv
        computer_name = socket.gethostname()
        dc_name = "\\\\" + dc_name
        print("DC Name : ", dc_name)
        print("DC IP : ", dc_ip)
        print("Computer Name : ", computer_name)
        print("Account Name : ", account_name)
        print("Account Password : ", account_password)
        print("Initiate Secure Channel ...")
        user = userlog(
            dc_name,
            computer_name,
            account_name,
            account_password,
            dc_ip)
        InitiateSecureChannel(user)

if __name__ == '__main__':
    main()
