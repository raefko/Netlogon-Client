from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from binascii import hexlify, unhexlify
from subprocess import check_call

import hmac, hashlib, struct, sys, socket, time, itertools, uuid

def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    sys.exit(2)

def ConnectRPCServer(dc_ip):
    rpc_con = None
    try :
        binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    return rpc_con

def authenticate(rpc_con, dc_name, computer_name, account_name, account_password, dc_ip):
    Client_Challenge = uuid.uuid4().hex.encode()
    status = nrpc.hNetrServerReqChallenge(rpc_con, dc_name, computer_name, Client_Challenge)
    if (status == None or status['ErrorCode'] != 0):
        fail(f'Error NetrServerReqChallenge')
    else:
        #status.dump()
        Server_Challenge = status['ServerChallenge']
        print("Client_Challenge : ", Client_Challenge)
        print("Server_Challenge : ", Server_Challenge)

def InitiateSecureChannel(dc_name, computer_name, account_name, account_password, dc_ip):
    rpc_con = ConnectRPCServer(dc_ip)
    try :
        authenticate(rpc_con, dc_name, computer_name, account_name, account_password, dc_ip)
    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            pass
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')


def main():
    if (len(sys.argv) != 6):
        print('Usage: netlogon_client.py <dc-name> <computer_name> <account_name> <account_password> <dc-ip>\n')
        print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
        sys.exit(1)
    else:
        print("Starting Client...")
        [_, dc_name, computer_name, account_name, account_password, dc_ip] = sys.argv
        print("DC Name : ", dc_name)
        print("DC IP : ", dc_ip)
        print("Computer Name : ", computer_name)
        print("Account Name : ", account_name)
        print("Account Password : ", account_password)
        print("Initiate Secure Channel ...")
        InitiateSecureChannel(dc_name, computer_name, account_name, account_password, dc_ip)

if __name__ == '__main__':
    main()