# Section 3.1.4.4.2
def ComputeNetlogonCredential(inputData, Sk):
    k1 = Sk[:7]
    k3 = crypto.transformKey(k1)
    k2 = Sk[7:14]
    k4 = crypto.transformKey(k2)
    Crypt1 = DES.new(k3, DES.MODE_ECB)
    Crypt2 = DES.new(k4, DES.MODE_ECB)
    cipherText = Crypt1.encrypt(inputData)
    return Crypt2.encrypt(cipherText)

# Section 3.1.4.4.1
def ComputeNetlogonCredentialAES(inputData, Sk):
    IV=b'\x00'*16
    Crypt1 = AES.new(Sk, AES.MODE_CFB, IV)
    return Crypt1.encrypt(inputData)

# Section 3.1.4.3.1
def ComputeSessionKeyAES(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # added the ability to receive hashes already
    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash
    hm = hmac.new(key=M4SS, digestmod=hashlib.sha256)
    hm.update(clientChallenge)
    hm.update(serverChallenge)
    sessionKey = hm.digest()

    return sessionKey[:16]

# 3.1.4.3.2 Strong-key Session-Key
def ComputeSessionKeyStrongKey(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # added the ability to receive hashes already

    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash

    md5 = hashlib.new('md5')
    md5.update(b'\x00'*4)
    md5.update(clientChallenge)
    md5.update(serverChallenge)
    finalMD5 = md5.digest()
    hm = hmac.new(M4SS, digestmod=hashlib.md5)
    hm.update(finalMD5)
    return hm.digest()

def deriveSequenceNumber(sequenceNum):
    sequenceLow = sequenceNum & 0xffffffff
    sequenceHigh = (sequenceNum >> 32) & 0xffffffff
    sequenceHigh |= 0x80000000

    res = pack('>L', sequenceLow)
    res += pack('>L', sequenceHigh)
    return res

def ComputeNetlogonSignatureAES(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    hm = hmac.new(key=sessionKey, digestmod=hashlib.sha256)
    hm.update(authSignature.getData()[:8])
    # If no confidentiality requested, it should be ''
    hm.update(confounder)
    hm.update(bytes(message))
    return hm.digest()[:8]+'\x00'*24

def ComputeNetlogonSignatureMD5(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    md5 = hashlib.new('md5')
    md5.update(b'\x00'*4)
    md5.update(authSignature.getData()[:8])
    # If no confidentiality requested, it should be ''
    md5.update(confounder)
    md5.update(bytes(message))
    finalMD5 = md5.digest()
    hm = hmac.new(sessionKey, digestmod=hashlib.md5)
    hm.update(finalMD5)
    return hm.digest()[:8]

def encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9

    hm = hmac.new(sessionKey, digestmod=hashlib.md5)
    hm.update(b'\x00'*4)
    hm2 = hmac.new(hm.digest(), digestmod=hashlib.md5)
    hm2.update(checkSum)
    encryptionKey = hm2.digest()

    cipher = ARC4.new(encryptionKey)
    return cipher.encrypt(sequenceNum)

def decryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.2, point 5

    return encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey)

def encryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.encrypt(sequenceNum)

def decryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.decrypt(sequenceNum)

def SIGN(data, confounder, sequenceNum, key, aes = False):
    if aes is False:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_MD5
        if confounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_RC4
        signature['Checksum'] = ComputeNetlogonSignatureMD5(signature, data, confounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberRC4(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature
    else:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_SHA256
        if confounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_AES128
        signature['Checksum'] = ComputeNetlogonSignatureAES(signature, data, confounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberAES(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature

def SEAL(data, confounder, sequenceNum, key, aes = False):
    signature = SIGN(data, confounder, sequenceNum, key, aes)
    sequenceNum = deriveSequenceNumber(sequenceNum)

    XorKey = bytearray(key)
    for i in range(len(XorKey)):
        XorKey[i] = XorKey[i] ^ 0xf0

    XorKey = bytes(XorKey)

    if aes is False:
        hm = hmac.new(XorKey, digestmod=hashlib.md5)
        hm.update(b'\x00'*4)
        hm2 = hmac.new(hm.digest(), digestmod=hashlib.md5)
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(confounder)
        cipher = ARC4.new(encryptionKey)
        encrypted = cipher.encrypt(data)

        signature['Confounder'] = cfounder

        return encrypted, signature
    else:
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.encrypt(confounder)
        encrypted = cipher.encrypt(data)

        signature['Confounder'] = cfounder

        return encrypted, signature

def UNSEAL(data, auth_data, key, aes = False):
    auth_data = NL_AUTH_SIGNATURE(auth_data)
    XorKey = bytearray(key)
    for i in range(len(XorKey)):
        XorKey[i] = XorKey[i] ^ 0xf0

    XorKey = bytes(XorKey)

    if aes is False:
        sequenceNum = decryptSequenceNumberRC4(auth_data['SequenceNumber'], auth_data['Checksum'],  key)
        hm = hmac.new(XorKey, digestmod=hashlib.md5)
        hm.update(b'\x00'*4)
        hm2 = hmac.new(hm.digest(), digestmod=hashlib.md5)
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(auth_data['Confounder'])
        cipher = ARC4.new(encryptionKey)
        plain = cipher.encrypt(data)

        return plain, cfounder
    else:
        sequenceNum = decryptSequenceNumberAES(auth_data['SequenceNumber'], auth_data['Checksum'],  key)
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.decrypt(auth_data['Confounder'])
        plain = cipher.decrypt(data)
        return plain, cfounder


def getSSPType1(workstation='', domain='', signingRequired=False):
    auth = NL_AUTH_MESSAGE()
    auth['Flags'] = 0
    auth['Buffer'] = b''
    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_DOMAIN
    if domain != '':
        auth['Buffer'] = auth['Buffer'] + b(domain) + b'\x00'
    else:
        auth['Buffer'] += b'WORKGROUP\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST

    if workstation != '':
        auth['Buffer'] = auth['Buffer'] + b(workstation) + b'\x00'
    else:
        auth['Buffer'] += b'MYHOST\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8

    if workstation != '':
        auth['Buffer'] += pack('<B',len(workstation)) + b(workstation) + b'\x00'
    else:
        auth['Buffer'] += b'\x06MYHOST\x00'

    return auth

    def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def hNetrServerReqChallenge(dce, primaryName, computerName, clientChallenge):
    request = NetrServerReqChallenge()
    request['PrimaryName'] = checkNullString(primaryName)
    request['ComputerName'] = checkNullString(computerName)
    request['ClientChallenge'] = clientChallenge
    return dce.request(request)

def hNetrServerAuthenticate3(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags):
    request = NetrServerAuthenticate3()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    request['NegotiateFlags'] = negotiateFlags
    return dce.request(request)

def hDsrGetDcNameEx2(dce, computerName, accountName, allowableAccountControlBits, domainName, domainGuid, siteName, flags):
    request = DsrGetDcNameEx2()
    request['ComputerName'] = checkNullString(computerName)
    request['AccountName'] = checkNullString(accountName)
    request['AllowableAccountControlBits'] = allowableAccountControlBits
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteName'] = checkNullString(siteName)
    request['Flags'] = flags
    return dce.request(request)

def hDsrGetDcNameEx(dce, computerName, domainName, domainGuid, siteName, flags):
    request = DsrGetDcNameEx()
    request['ComputerName'] = checkNullString(computerName)
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteName'] = siteName
    request['Flags'] = flags
    return dce.request(request)

def hDsrGetDcName(dce, computerName, domainName, domainGuid, siteGuid, flags):
    request = DsrGetDcName()
    request['ComputerName'] = checkNullString(computerName)
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteGuid'] = siteGuid
    request['Flags'] = flags
    return dce.request(request)

def hNetrGetAnyDCName(dce, serverName, domainName):
    request = NetrGetAnyDCName()
    request['ServerName'] = checkNullString(serverName)
    request['DomainName'] = checkNullString(domainName)
    return dce.request(request)

def hNetrGetDCName(dce, serverName, domainName):
    request = NetrGetDCName()
    request['ServerName'] = checkNullString(serverName)
    request['DomainName'] = checkNullString(domainName)
    return dce.request(request)

def hDsrGetSiteName(dce, computerName):
    request = DsrGetSiteName()
    request['ComputerName'] = checkNullString(computerName)
    return dce.request(request)

def hDsrGetDcSiteCoverageW(dce, serverName):
    request = DsrGetDcSiteCoverageW()
    request['ServerName'] = checkNullString(serverName)
    return dce.request(request)

def hNetrServerAuthenticate2(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags):
    request = NetrServerAuthenticate2()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    request['NegotiateFlags'] = negotiateFlags
    return dce.request(request)

def hNetrServerAuthenticate(dce, primaryName, accountName, secureChannelType, computerName, clientCredential):
    request = NetrServerAuthenticate()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    return dce.request(request)

def hNetrServerPasswordGet(dce, primaryName, accountName, accountType, computerName, authenticator):
    request = NetrServerPasswordGet()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['AccountType'] = accountType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)

def hNetrServerTrustPasswordsGet(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator):
    request = NetrServerTrustPasswordsGet()
    request['TrustedDcName'] = checkNullString(trustedDcName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)

def hNetrServerPasswordSet2(dce, primaryName, accountName, secureChannelType, computerName, authenticator, clearNewPasswordBlob):
    request = NetrServerPasswordSet2()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    request['ClearNewPassword'] = clearNewPasswordBlob
    return dce.request(request)

def hNetrLogonGetDomainInfo(dce, serverName, computerName, authenticator, returnAuthenticator=0, level=1):
    request = NetrLogonGetDomainInfo()
    request['ServerName'] = checkNullString(serverName)
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    if returnAuthenticator == 0:
        request['ReturnAuthenticator']['Credential'] = b'\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
    else:
        request['ReturnAuthenticator'] = returnAuthenticator

    request['Level'] = 1
    if level == 1:
        request['WkstaBuffer']['tag'] = 1
        request['WkstaBuffer']['WorkstationInfo']['DnsHostName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['SiteName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['OsName'] = ''
        request['WkstaBuffer']['WorkstationInfo']['Dummy1'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['Dummy2'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['Dummy3'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['Dummy4'] = NULL
    else:
        request['WkstaBuffer']['tag'] = 2
        request['WkstaBuffer']['LsaPolicyInfo']['LsaPolicy'] = NULL
    return dce.request(request)

def hNetrLogonGetCapabilities(dce, serverName, computerName, authenticator, returnAuthenticator=0, queryLevel=1):
    request = NetrLogonGetCapabilities()
    request['ServerName'] = checkNullString(serverName)
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    if returnAuthenticator == 0:
        request['ReturnAuthenticator']['Credential'] = b'\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
    else:
        request['ReturnAuthenticator'] = returnAuthenticator
    request['QueryLevel'] = queryLevel
    return dce.request(request)

def hNetrServerGetTrustInfo(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator):
    request = NetrServerGetTrustInfo()
    request['TrustedDcName'] = checkNullString(trustedDcName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)
