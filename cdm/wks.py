import binascii
import os
import base64
from google.protobuf import descriptor as _descriptor, descriptor_pool as _descriptor_pool, symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import os
import time
import binascii
import logging
import subprocess
import re
import base64
import requests
from base64 import b64encode
from google.protobuf.message import DecodeError
from google.protobuf import text_format
import xmltodict
import base64
import uuid
import requests
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random import random
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import CMAC, SHA256, HMAC, SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Util import Padding
import logging
from bs4 import BeautifulSoup

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
  b'\n\x0fwv_proto2.proto\"\xe7\x05\n\x14\x43lientIdentification\x12-\n\x04Type\x18\x01 \x02(\x0e\x32\x1f.ClientIdentification.TokenType\x12\'\n\x05Token\x18\x02 \x01(\x0b\x32\x18.SignedDeviceCertificate\x12\x33\n\nClientInfo\x18\x03 \x03(\x0b\x32\x1f.ClientIdentification.NameValue\x12\x1b\n\x13ProviderClientToken\x18\x04 \x01(\x0c\x12\x16\n\x0eLicenseCounter\x18\x05 \x01(\r\x12\x45\n\x13_ClientCapabilities\x18\x06 \x01(\x0b\x32(.ClientIdentification.ClientCapabilities\x12 \n\x0b_FileHashes\x18\x07 \x01(\x0b\x32\x0b.FileHashes\x1a(\n\tNameValue\x12\x0c\n\x04Name\x18\x01 \x02(\t\x12\r\n\x05Value\x18\x02 \x02(\t\x1a\xa4\x02\n\x12\x43lientCapabilities\x12\x13\n\x0b\x43lientToken\x18\x01 \x01(\r\x12\x14\n\x0cSessionToken\x18\x02 \x01(\r\x12\"\n\x1aVideoResolutionConstraints\x18\x03 \x01(\r\x12L\n\x0eMaxHdcpVersion\x18\x04 \x01(\x0e\x32\x34.ClientIdentification.ClientCapabilities.HdcpVersion\x12\x1b\n\x13OemCryptoApiVersion\x18\x05 \x01(\r\"T\n\x0bHdcpVersion\x12\r\n\tHDCP_NONE\x10\x00\x12\x0b\n\x07HDCP_V1\x10\x01\x12\x0b\n\x07HDCP_V2\x10\x02\x12\r\n\tHDCP_V2_1\x10\x03\x12\r\n\tHDCP_V2_2\x10\x04\"S\n\tTokenType\x12\n\n\x06KEYBOX\x10\x00\x12\x16\n\x12\x44\x45VICE_CERTIFICATE\x10\x01\x12\"\n\x1eREMOTE_ATTESTATION_CERTIFICATE\x10\x02\"\x9b\x02\n\x11\x44\x65viceCertificate\x12\x30\n\x04Type\x18\x01 \x02(\x0e\x32\".DeviceCertificate.CertificateType\x12\x14\n\x0cSerialNumber\x18\x02 \x01(\x0c\x12\x1b\n\x13\x43reationTimeSeconds\x18\x03 \x01(\r\x12\x11\n\tPublicKey\x18\x04 \x01(\x0c\x12\x10\n\x08SystemId\x18\x05 \x01(\r\x12\x1c\n\x14TestDeviceDeprecated\x18\x06 \x01(\r\x12\x11\n\tServiceId\x18\x07 \x01(\x0c\"K\n\x0f\x43\x65rtificateType\x12\x08\n\x04ROOT\x10\x00\x12\x10\n\x0cINTERMEDIATE\x10\x01\x12\x0f\n\x0bUSER_DEVICE\x10\x02\x12\x0b\n\x07SERVICE\x10\x03\"\xc4\x01\n\x17\x44\x65viceCertificateStatus\x12\x14\n\x0cSerialNumber\x18\x01 \x01(\x0c\x12:\n\x06Status\x18\x02 \x01(\x0e\x32*.DeviceCertificateStatus.CertificateStatus\x12*\n\nDeviceInfo\x18\x04 \x01(\x0b\x32\x16.ProvisionedDeviceInfo\"+\n\x11\x43\x65rtificateStatus\x12\t\n\x05VALID\x10\x00\x12\x0b\n\x07REVOKED\x10\x01\"o\n\x1b\x44\x65viceCertificateStatusList\x12\x1b\n\x13\x43reationTimeSeconds\x18\x01 \x01(\r\x12\x33\n\x11\x43\x65rtificateStatus\x18\x02 \x03(\x0b\x32\x18.DeviceCertificateStatus\"\xaf\x01\n\x1d\x45ncryptedClientIdentification\x12\x11\n\tServiceId\x18\x01 \x02(\t\x12&\n\x1eServiceCertificateSerialNumber\x18\x02 \x01(\x0c\x12\x19\n\x11\x45ncryptedClientId\x18\x03 \x02(\x0c\x12\x1b\n\x13\x45ncryptedClientIdIv\x18\x04 \x02(\x0c\x12\x1b\n\x13\x45ncryptedPrivacyKey\x18\x05 \x02(\x0c\"\x9c\x01\n\x15LicenseIdentification\x12\x11\n\tRequestId\x18\x01 \x01(\x0c\x12\x11\n\tSessionId\x18\x02 \x01(\x0c\x12\x12\n\nPurchaseId\x18\x03 \x01(\x0c\x12\x1a\n\x04Type\x18\x04 \x01(\x0e\x32\x0c.LicenseType\x12\x0f\n\x07Version\x18\x05 \x01(\r\x12\x1c\n\x14ProviderSessionToken\x18\x06 \x01(\x0c\"\xa1\x0e\n\x07License\x12\"\n\x02Id\x18\x01 \x01(\x0b\x32\x16.LicenseIdentification\x12 \n\x07_Policy\x18\x02 \x01(\x0b\x32\x0f.License.Policy\x12\"\n\x03Key\x18\x03 \x03(\x0b\x32\x15.License.KeyContainer\x12\x18\n\x10LicenseStartTime\x18\x04 \x01(\r\x12!\n\x19RemoteAttestationVerified\x18\x05 \x01(\r\x12\x1b\n\x13ProviderClientToken\x18\x06 \x01(\x0c\x12\x18\n\x10ProtectionScheme\x18\x07 \x01(\r\x1a\xbb\x02\n\x06Policy\x12\x0f\n\x07\x43\x61nPlay\x18\x01 \x01(\x08\x12\x12\n\nCanPersist\x18\x02 \x01(\x08\x12\x10\n\x08\x43\x61nRenew\x18\x03 \x01(\x08\x12\x1d\n\x15RentalDurationSeconds\x18\x04 \x01(\r\x12\x1f\n\x17PlaybackDurationSeconds\x18\x05 \x01(\r\x12\x1e\n\x16LicenseDurationSeconds\x18\x06 \x01(\r\x12&\n\x1eRenewalRecoveryDurationSeconds\x18\x07 \x01(\r\x12\x18\n\x10RenewalServerUrl\x18\x08 \x01(\t\x12\x1b\n\x13RenewalDelaySeconds\x18\t \x01(\r\x12#\n\x1bRenewalRetryIntervalSeconds\x18\n \x01(\r\x12\x16\n\x0eRenewWithUsage\x18\x0b \x01(\x08\x1a\xf9\t\n\x0cKeyContainer\x12\n\n\x02Id\x18\x01 \x01(\x0c\x12\n\n\x02Iv\x18\x02 \x01(\x0c\x12\x0b\n\x03Key\x18\x03 \x01(\x0c\x12+\n\x04Type\x18\x04 \x01(\x0e\x32\x1d.License.KeyContainer.KeyType\x12\x32\n\x05Level\x18\x05 \x01(\x0e\x32#.License.KeyContainer.SecurityLevel\x12\x42\n\x12RequiredProtection\x18\x06 \x01(\x0b\x32&.License.KeyContainer.OutputProtection\x12\x43\n\x13RequestedProtection\x18\x07 \x01(\x0b\x32&.License.KeyContainer.OutputProtection\x12\x35\n\x0b_KeyControl\x18\x08 \x01(\x0b\x32 .License.KeyContainer.KeyControl\x12[\n\x1e_OperatorSessionKeyPermissions\x18\t \x01(\x0b\x32\x33.License.KeyContainer.OperatorSessionKeyPermissions\x12S\n\x1aVideoResolutionConstraints\x18\n \x03(\x0b\x32/.License.KeyContainer.VideoResolutionConstraint\x1a\xdb\x01\n\x10OutputProtection\x12\x42\n\x04Hdcp\x18\x01 \x01(\x0e\x32\x34.ClientIdentification.ClientCapabilities.HdcpVersion\x12>\n\tCgmsFlags\x18\x02 \x01(\x0e\x32+.License.KeyContainer.OutputProtection.CGMS\"C\n\x04\x43GMS\x12\r\n\tCOPY_FREE\x10\x00\x12\r\n\tCOPY_ONCE\x10\x02\x12\x0e\n\nCOPY_NEVER\x10\x03\x12\r\n\tCGMS_NONE\x10*\x1a\x31\n\nKeyControl\x12\x17\n\x0fKeyControlBlock\x18\x01 \x02(\x0c\x12\n\n\x02Iv\x18\x02 \x01(\x0c\x1a|\n\x1dOperatorSessionKeyPermissions\x12\x14\n\x0c\x41llowEncrypt\x18\x01 \x01(\r\x12\x14\n\x0c\x41llowDecrypt\x18\x02 \x01(\r\x12\x11\n\tAllowSign\x18\x03 \x01(\r\x12\x1c\n\x14\x41llowSignatureVerify\x18\x04 \x01(\r\x1a\x99\x01\n\x19VideoResolutionConstraint\x12\x1b\n\x13MinResolutionPixels\x18\x01 \x01(\r\x12\x1b\n\x13MaxResolutionPixels\x18\x02 \x01(\r\x12\x42\n\x12RequiredProtection\x18\x03 \x01(\x0b\x32&.License.KeyContainer.OutputProtection\"J\n\x07KeyType\x12\x0b\n\x07SIGNING\x10\x01\x12\x0b\n\x07\x43ONTENT\x10\x02\x12\x0f\n\x0bKEY_CONTROL\x10\x03\x12\x14\n\x10OPERATOR_SESSION\x10\x04\"z\n\rSecurityLevel\x12\x14\n\x10SW_SECURE_CRYPTO\x10\x01\x12\x14\n\x10SW_SECURE_DECODE\x10\x02\x12\x14\n\x10HW_SECURE_CRYPTO\x10\x03\x12\x14\n\x10HW_SECURE_DECODE\x10\x04\x12\x11\n\rHW_SECURE_ALL\x10\x05\"\x98\x01\n\x0cLicenseError\x12&\n\tErrorCode\x18\x01 \x01(\x0e\x32\x13.LicenseError.Error\"`\n\x05\x45rror\x12\x1e\n\x1aINVALID_DEVICE_CERTIFICATE\x10\x01\x12\x1e\n\x1aREVOKED_DEVICE_CERTIFICATE\x10\x02\x12\x17\n\x13SERVICE_UNAVAILABLE\x10\x03\"\xac\x07\n\x0eLicenseRequest\x12\'\n\x08\x43lientId\x18\x01 \x01(\x0b\x32\x15.ClientIdentification\x12\x38\n\tContentId\x18\x02 \x01(\x0b\x32%.LicenseRequest.ContentIdentification\x12)\n\x04Type\x18\x03 \x01(\x0e\x32\x1b.LicenseRequest.RequestType\x12\x13\n\x0bRequestTime\x18\x04 \x01(\r\x12!\n\x19KeyControlNonceDeprecated\x18\x05 \x01(\x0c\x12)\n\x0fProtocolVersion\x18\x06 \x01(\x0e\x32\x10.ProtocolVersion\x12\x17\n\x0fKeyControlNonce\x18\x07 \x01(\r\x12\x39\n\x11\x45ncryptedClientId\x18\x08 \x01(\x0b\x32\x1e.EncryptedClientIdentification\x1a\xa2\x04\n\x15\x43ontentIdentification\x12:\n\x06\x43\x65ncId\x18\x01 \x01(\x0b\x32*.LicenseRequest.ContentIdentification.CENC\x12:\n\x06WebmId\x18\x02 \x01(\x0b\x32*.LicenseRequest.ContentIdentification.WebM\x12\x46\n\x07License\x18\x03 \x01(\x0b\x32\x35.LicenseRequest.ContentIdentification.ExistingLicense\x1a_\n\x04\x43\x45NC\x12!\n\x04Pssh\x18\x01 \x01(\x0b\x32\x13.WidevineCencHeader\x12!\n\x0bLicenseType\x18\x02 \x01(\x0e\x32\x0c.LicenseType\x12\x11\n\tRequestId\x18\x03 \x01(\x0c\x1aL\n\x04WebM\x12\x0e\n\x06Header\x18\x01 \x01(\x0c\x12!\n\x0bLicenseType\x18\x02 \x01(\x0e\x32\x0c.LicenseType\x12\x11\n\tRequestId\x18\x03 \x01(\x0c\x1a\x99\x01\n\x0f\x45xistingLicense\x12)\n\tLicenseId\x18\x01 \x01(\x0b\x32\x16.LicenseIdentification\x12\x1b\n\x13SecondsSinceStarted\x18\x02 \x01(\r\x12\x1e\n\x16SecondsSinceLastPlayed\x18\x03 \x01(\r\x12\x1e\n\x16SessionUsageTableEntry\x18\x04 \x01(\x0c\"0\n\x0bRequestType\x12\x07\n\x03NEW\x10\x01\x12\x0b\n\x07RENEWAL\x10\x02\x12\x0b\n\x07RELEASE\x10\x03\"\xa9\x07\n\x11LicenseRequestRaw\x12\'\n\x08\x43lientId\x18\x01 \x01(\x0b\x32\x15.ClientIdentification\x12;\n\tContentId\x18\x02 \x01(\x0b\x32(.LicenseRequestRaw.ContentIdentification\x12,\n\x04Type\x18\x03 \x01(\x0e\x32\x1e.LicenseRequestRaw.RequestType\x12\x13\n\x0bRequestTime\x18\x04 \x01(\r\x12!\n\x19KeyControlNonceDeprecated\x18\x05 \x01(\x0c\x12)\n\x0fProtocolVersion\x18\x06 \x01(\x0e\x32\x10.ProtocolVersion\x12\x17\n\x0fKeyControlNonce\x18\x07 \x01(\r\x12\x39\n\x11\x45ncryptedClientId\x18\x08 \x01(\x0b\x32\x1e.EncryptedClientIdentification\x1a\x96\x04\n\x15\x43ontentIdentification\x12=\n\x06\x43\x65ncId\x18\x01 \x01(\x0b\x32-.LicenseRequestRaw.ContentIdentification.CENC\x12=\n\x06WebmId\x18\x02 \x01(\x0b\x32-.LicenseRequestRaw.ContentIdentification.WebM\x12I\n\x07License\x18\x03 \x01(\x0b\x32\x38.LicenseRequestRaw.ContentIdentification.ExistingLicense\x1aJ\n\x04\x43\x45NC\x12\x0c\n\x04Pssh\x18\x01 \x01(\x0c\x12!\n\x0bLicenseType\x18\x02 \x01(\x0e\x32\x0c.LicenseType\x12\x11\n\tRequestId\x18\x03 \x01(\x0c\x1aL\n\x04WebM\x12\x0e\n\x06Header\x18\x01 \x01(\x0c\x12!\n\x0bLicenseType\x18\x02 \x01(\x0e\x32\x0c.LicenseType\x12\x11\n\tRequestId\x18\x03 \x01(\x0c\x1a\x99\x01\n\x0f\x45xistingLicense\x12)\n\tLicenseId\x18\x01 \x01(\x0b\x32\x16.LicenseIdentification\x12\x1b\n\x13SecondsSinceStarted\x18\x02 \x01(\r\x12\x1e\n\x16SecondsSinceLastPlayed\x18\x03 \x01(\r\x12\x1e\n\x16SessionUsageTableEntry\x18\x04 \x01(\x0c\"0\n\x0bRequestType\x12\x07\n\x03NEW\x10\x01\x12\x0b\n\x07RENEWAL\x10\x02\x12\x0b\n\x07RELEASE\x10\x03\"\xa6\x02\n\x15ProvisionedDeviceInfo\x12\x10\n\x08SystemId\x18\x01 \x01(\r\x12\x0b\n\x03Soc\x18\x02 \x01(\t\x12\x14\n\x0cManufacturer\x18\x03 \x01(\t\x12\r\n\x05Model\x18\x04 \x01(\t\x12\x12\n\nDeviceType\x18\x05 \x01(\t\x12\x11\n\tModelYear\x18\x06 \x01(\r\x12=\n\rSecurityLevel\x18\x07 \x01(\x0e\x32&.ProvisionedDeviceInfo.WvSecurityLevel\x12\x12\n\nTestDevice\x18\x08 \x01(\r\"O\n\x0fWvSecurityLevel\x12\x15\n\x11LEVEL_UNSPECIFIED\x10\x00\x12\x0b\n\x07LEVEL_1\x10\x01\x12\x0b\n\x07LEVEL_2\x10\x02\x12\x0b\n\x07LEVEL_3\x10\x03\"\x15\n\x13ProvisioningOptions\"\x15\n\x13ProvisioningRequest\"\x16\n\x14ProvisioningResponse\"i\n\x11RemoteAttestation\x12\x33\n\x0b\x43\x65rtificate\x18\x01 \x01(\x0b\x32\x1e.EncryptedClientIdentification\x12\x0c\n\x04Salt\x18\x02 \x01(\t\x12\x11\n\tSignature\x18\x03 \x01(\t\"\r\n\x0bSessionInit\"\x0e\n\x0cSessionState\"\x1d\n\x1bSignedCertificateStatusList\"\x86\x01\n\x17SignedDeviceCertificate\x12.\n\x12_DeviceCertificate\x18\x01 \x01(\x0b\x32\x12.DeviceCertificate\x12\x11\n\tSignature\x18\x02 \x01(\x0c\x12(\n\x06Signer\x18\x03 \x01(\x0b\x32\x18.SignedDeviceCertificate\"\x1b\n\x19SignedProvisioningMessage\"\x9b\x02\n\rSignedMessage\x12(\n\x04Type\x18\x01 \x01(\x0e\x32\x1a.SignedMessage.MessageType\x12\x0b\n\x03Msg\x18\x02 \x01(\x0c\x12\x11\n\tSignature\x18\x03 \x01(\x0c\x12\x12\n\nSessionKey\x18\x04 \x01(\x0c\x12-\n\x11RemoteAttestation\x18\x05 \x01(\x0b\x32\x12.RemoteAttestation\"}\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\"\xc5\x02\n\x12WidevineCencHeader\x12\x30\n\talgorithm\x18\x01 \x01(\x0e\x32\x1d.WidevineCencHeader.Algorithm\x12\x0e\n\x06key_id\x18\x02 \x03(\x0c\x12\x10\n\x08provider\x18\x03 \x01(\t\x12\x12\n\ncontent_id\x18\x04 \x01(\x0c\x12\x1d\n\x15track_type_deprecated\x18\x05 \x01(\t\x12\x0e\n\x06policy\x18\x06 \x01(\t\x12\x1b\n\x13\x63rypto_period_index\x18\x07 \x01(\r\x12\x17\n\x0fgrouped_license\x18\x08 \x01(\x0c\x12\x19\n\x11protection_scheme\x18\t \x01(\r\x12\x1d\n\x15\x63rypto_period_seconds\x18\n \x01(\r\"(\n\tAlgorithm\x12\x0f\n\x0bUNENCRYPTED\x10\x00\x12\n\n\x06\x41\x45SCTR\x10\x01\"\xba\x02\n\x14SignedLicenseRequest\x12/\n\x04Type\x18\x01 \x01(\x0e\x32!.SignedLicenseRequest.MessageType\x12\x1c\n\x03Msg\x18\x02 \x01(\x0b\x32\x0f.LicenseRequest\x12\x11\n\tSignature\x18\x03 \x01(\x0c\x12\x12\n\nSessionKey\x18\x04 \x01(\x0c\x12-\n\x11RemoteAttestation\x18\x05 \x01(\x0b\x32\x12.RemoteAttestation\"}\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\"\xc3\x02\n\x17SignedLicenseRequestRaw\x12\x32\n\x04Type\x18\x01 \x01(\x0e\x32$.SignedLicenseRequestRaw.MessageType\x12\x1f\n\x03Msg\x18\x02 \x01(\x0b\x32\x12.LicenseRequestRaw\x12\x11\n\tSignature\x18\x03 \x01(\x0c\x12\x12\n\nSessionKey\x18\x04 \x01(\x0c\x12-\n\x11RemoteAttestation\x18\x05 \x01(\x0b\x32\x12.RemoteAttestation\"}\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\"\xa5\x02\n\rSignedLicense\x12(\n\x04Type\x18\x01 \x01(\x0e\x32\x1a.SignedLicense.MessageType\x12\x15\n\x03Msg\x18\x02 \x01(\x0b\x32\x08.License\x12\x11\n\tSignature\x18\x03 \x01(\x0c\x12\x12\n\nSessionKey\x18\x04 \x01(\x0c\x12-\n\x11RemoteAttestation\x18\x05 \x01(\x0b\x32\x12.RemoteAttestation\"}\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\"\xcb\x02\n\x18SignedServiceCertificate\x12\x33\n\x04Type\x18\x01 \x01(\x0e\x32%.SignedServiceCertificate.MessageType\x12%\n\x03Msg\x18\x02 \x01(\x0b\x32\x18.SignedDeviceCertificate\x12\x11\n\tSignature\x18\x03 \x01(\x0c\x12\x12\n\nSessionKey\x18\x04 \x01(\x0c\x12-\n\x11RemoteAttestation\x18\x05 \x01(\x0b\x32\x12.RemoteAttestation\"}\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\"\xb5\x01\n\nFileHashes\x12\x0e\n\x06signer\x18\x01 \x01(\x0c\x12)\n\nsignatures\x18\x02 \x03(\x0b\x32\x15.FileHashes.Signature\x1al\n\tSignature\x12\x10\n\x08\x66ilename\x18\x01 \x01(\t\x12\x14\n\x0ctest_signing\x18\x02 \x01(\x08\x12\x12\n\nSHA512Hash\x18\x03 \x01(\x0c\x12\x10\n\x08main_exe\x18\x04 \x01(\x08\x12\x11\n\tsignature\x18\x05 \x01(\x0c*1\n\x0bLicenseType\x12\x08\n\x04ZERO\x10\x00\x12\x0b\n\x07\x44\x45\x46\x41ULT\x10\x01\x12\x0b\n\x07OFFLINE\x10\x02*\x1e\n\x0fProtocolVersion\x12\x0b\n\x07\x43URRENT\x10\x15')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'wv_proto2_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _LICENSETYPE._serialized_start = 8339
  _LICENSETYPE._serialized_end = 8388
  _PROTOCOLVERSION._serialized_start = 8390
  _PROTOCOLVERSION._serialized_end = 8420
  _CLIENTIDENTIFICATION._serialized_start = 20
  _CLIENTIDENTIFICATION._serialized_end = 763
  _CLIENTIDENTIFICATION_NAMEVALUE._serialized_start = 343
  _CLIENTIDENTIFICATION_NAMEVALUE._serialized_end = 383
  _CLIENTIDENTIFICATION_CLIENTCAPABILITIES._serialized_start = 386
  _CLIENTIDENTIFICATION_CLIENTCAPABILITIES._serialized_end = 678
  _CLIENTIDENTIFICATION_CLIENTCAPABILITIES_HDCPVERSION._serialized_start = 594
  _CLIENTIDENTIFICATION_CLIENTCAPABILITIES_HDCPVERSION._serialized_end = 678
  _CLIENTIDENTIFICATION_TOKENTYPE._serialized_start = 680
  _CLIENTIDENTIFICATION_TOKENTYPE._serialized_end = 763
  _DEVICECERTIFICATE._serialized_start = 766
  _DEVICECERTIFICATE._serialized_end = 1049
  _DEVICECERTIFICATE_CERTIFICATETYPE._serialized_start = 974
  _DEVICECERTIFICATE_CERTIFICATETYPE._serialized_end = 1049
  _DEVICECERTIFICATESTATUS._serialized_start = 1052
  _DEVICECERTIFICATESTATUS._serialized_end = 1248
  _DEVICECERTIFICATESTATUS_CERTIFICATESTATUS._serialized_start = 1205
  _DEVICECERTIFICATESTATUS_CERTIFICATESTATUS._serialized_end = 1248
  _DEVICECERTIFICATESTATUSLIST._serialized_start = 1250
  _DEVICECERTIFICATESTATUSLIST._serialized_end = 1361
  _ENCRYPTEDCLIENTIDENTIFICATION._serialized_start = 1364
  _ENCRYPTEDCLIENTIDENTIFICATION._serialized_end = 1539
  _LICENSEIDENTIFICATION._serialized_start = 1542
  _LICENSEIDENTIFICATION._serialized_end = 1698
  _LICENSE._serialized_start = 1701
  _LICENSE._serialized_end = 3526
  _LICENSE_POLICY._serialized_start = 1935
  _LICENSE_POLICY._serialized_end = 2250
  _LICENSE_KEYCONTAINER._serialized_start = 2253
  _LICENSE_KEYCONTAINER._serialized_end = 3526
  _LICENSE_KEYCONTAINER_OUTPUTPROTECTION._serialized_start = 2774
  _LICENSE_KEYCONTAINER_OUTPUTPROTECTION._serialized_end = 2993
  _LICENSE_KEYCONTAINER_OUTPUTPROTECTION_CGMS._serialized_start = 2926
  _LICENSE_KEYCONTAINER_OUTPUTPROTECTION_CGMS._serialized_end = 2993
  _LICENSE_KEYCONTAINER_KEYCONTROL._serialized_start = 2995
  _LICENSE_KEYCONTAINER_KEYCONTROL._serialized_end = 3044
  _LICENSE_KEYCONTAINER_OPERATORSESSIONKEYPERMISSIONS._serialized_start = 3046
  _LICENSE_KEYCONTAINER_OPERATORSESSIONKEYPERMISSIONS._serialized_end = 3170
  _LICENSE_KEYCONTAINER_VIDEORESOLUTIONCONSTRAINT._serialized_start = 3173
  _LICENSE_KEYCONTAINER_VIDEORESOLUTIONCONSTRAINT._serialized_end = 3326
  _LICENSE_KEYCONTAINER_KEYTYPE._serialized_start = 3328
  _LICENSE_KEYCONTAINER_KEYTYPE._serialized_end = 3402
  _LICENSE_KEYCONTAINER_SECURITYLEVEL._serialized_start = 3404
  _LICENSE_KEYCONTAINER_SECURITYLEVEL._serialized_end = 3526
  _LICENSEERROR._serialized_start = 3529
  _LICENSEERROR._serialized_end = 3681
  _LICENSEERROR_ERROR._serialized_start = 3585
  _LICENSEERROR_ERROR._serialized_end = 3681
  _LICENSEREQUEST._serialized_start = 3684
  _LICENSEREQUEST._serialized_end = 4624
  _LICENSEREQUEST_CONTENTIDENTIFICATION._serialized_start = 4028
  _LICENSEREQUEST_CONTENTIDENTIFICATION._serialized_end = 4574
  _LICENSEREQUEST_CONTENTIDENTIFICATION_CENC._serialized_start = 4245
  _LICENSEREQUEST_CONTENTIDENTIFICATION_CENC._serialized_end = 4340
  _LICENSEREQUEST_CONTENTIDENTIFICATION_WEBM._serialized_start = 4342
  _LICENSEREQUEST_CONTENTIDENTIFICATION_WEBM._serialized_end = 4418
  _LICENSEREQUEST_CONTENTIDENTIFICATION_EXISTINGLICENSE._serialized_start = 4421
  _LICENSEREQUEST_CONTENTIDENTIFICATION_EXISTINGLICENSE._serialized_end = 4574
  _LICENSEREQUEST_REQUESTTYPE._serialized_start = 4576
  _LICENSEREQUEST_REQUESTTYPE._serialized_end = 4624
  _LICENSEREQUESTRAW._serialized_start = 4627
  _LICENSEREQUESTRAW._serialized_end = 5564
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION._serialized_start = 4980
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION._serialized_end = 5514
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_CENC._serialized_start = 5206
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_CENC._serialized_end = 5280
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_WEBM._serialized_start = 4342
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_WEBM._serialized_end = 4418
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_EXISTINGLICENSE._serialized_start = 4421
  _LICENSEREQUESTRAW_CONTENTIDENTIFICATION_EXISTINGLICENSE._serialized_end = 4574
  _LICENSEREQUESTRAW_REQUESTTYPE._serialized_start = 4576
  _LICENSEREQUESTRAW_REQUESTTYPE._serialized_end = 4624
  _PROVISIONEDDEVICEINFO._serialized_start = 5567
  _PROVISIONEDDEVICEINFO._serialized_end = 5861
  _PROVISIONEDDEVICEINFO_WVSECURITYLEVEL._serialized_start = 5782
  _PROVISIONEDDEVICEINFO_WVSECURITYLEVEL._serialized_end = 5861
  _PROVISIONINGOPTIONS._serialized_start = 5863
  _PROVISIONINGOPTIONS._serialized_end = 5884
  _PROVISIONINGREQUEST._serialized_start = 5886
  _PROVISIONINGREQUEST._serialized_end = 5907
  _PROVISIONINGRESPONSE._serialized_start = 5909
  _PROVISIONINGRESPONSE._serialized_end = 5931
  _REMOTEATTESTATION._serialized_start = 5933
  _REMOTEATTESTATION._serialized_end = 6038
  _SESSIONINIT._serialized_start = 6040
  _SESSIONINIT._serialized_end = 6053
  _SESSIONSTATE._serialized_start = 6055
  _SESSIONSTATE._serialized_end = 6069
  _SIGNEDCERTIFICATESTATUSLIST._serialized_start = 6071
  _SIGNEDCERTIFICATESTATUSLIST._serialized_end = 6100
  _SIGNEDDEVICECERTIFICATE._serialized_start = 6103
  _SIGNEDDEVICECERTIFICATE._serialized_end = 6237
  _SIGNEDPROVISIONINGMESSAGE._serialized_start = 6239
  _SIGNEDPROVISIONINGMESSAGE._serialized_end = 6266
  _SIGNEDMESSAGE._serialized_start = 6269
  _SIGNEDMESSAGE._serialized_end = 6552
  _SIGNEDMESSAGE_MESSAGETYPE._serialized_start = 6427
  _SIGNEDMESSAGE_MESSAGETYPE._serialized_end = 6552
  _WIDEVINECENCHEADER._serialized_start = 6555
  _WIDEVINECENCHEADER._serialized_end = 6880
  _WIDEVINECENCHEADER_ALGORITHM._serialized_start = 6840
  _WIDEVINECENCHEADER_ALGORITHM._serialized_end = 6880
  _SIGNEDLICENSEREQUEST._serialized_start = 6883
  _SIGNEDLICENSEREQUEST._serialized_end = 7197
  _SIGNEDLICENSEREQUEST_MESSAGETYPE._serialized_start = 6427
  _SIGNEDLICENSEREQUEST_MESSAGETYPE._serialized_end = 6552
  _SIGNEDLICENSEREQUESTRAW._serialized_start = 7200
  _SIGNEDLICENSEREQUESTRAW._serialized_end = 7523
  _SIGNEDLICENSEREQUESTRAW_MESSAGETYPE._serialized_start = 6427
  _SIGNEDLICENSEREQUESTRAW_MESSAGETYPE._serialized_end = 6552
  _SIGNEDLICENSE._serialized_start = 7526
  _SIGNEDLICENSE._serialized_end = 7819
  _SIGNEDLICENSE_MESSAGETYPE._serialized_start = 6427
  _SIGNEDLICENSE_MESSAGETYPE._serialized_end = 6552
  _SIGNEDSERVICECERTIFICATE._serialized_start = 7822
  _SIGNEDSERVICECERTIFICATE._serialized_end = 8153
  _SIGNEDSERVICECERTIFICATE_MESSAGETYPE._serialized_start = 6427
  _SIGNEDSERVICECERTIFICATE_MESSAGETYPE._serialized_end = 6552
  _FILEHASHES._serialized_start = 8156
  _FILEHASHES._serialized_end = 8337
  _FILEHASHES_SIGNATURE._serialized_start = 8229
  _FILEHASHES_SIGNATURE._serialized_end = 8337
# @@protoc_insertion_point(module_scope)

class Session:
    def __init__(self, session_id, init_data, device_config, offline):
        self.session_id = session_id
        self.init_data = init_data
        self.offline = offline
        self.device_config = device_config
        self.device_key = None
        self.session_key = None
        self.derived_keys = {
            'enc': None,
            'auth_1': None,
            'auth_2': None
        }
        self.license_request = None
        self.license = None
        self.service_certificate = None
        self.privacy_mode = False
        self.keys = []

class Key:
    def __init__(self, kid, type, key, permissions=[]):
        self.kid = kid
        self.type = type
        self.key = key
        self.permissions = permissions

    def __repr__(self):
        if self.type == "OPERATOR_SESSION":
           return "key(kid={}, type={}, key={}, permissions={})".format(self.kid, self.type, binascii.hexlify(self.key), self.permissions)
        else:
           return "key(kid={}, type={}, key={})".format(self.kid, self.type, binascii.hexlify(self.key))

try:
    from google.protobuf.internal.decoder import _DecodeVarint as _di
except ImportError:
    def LEB128_decode(buffer, pos, limit=64):
        result = 0
        shift = 0
        while True:
            b = buffer[pos]
            pos += 1  
            result |= ((b & 0x7F) << shift)
            if not (b & 0x80): 
                return (result, pos)
            shift += 7
            if shift > limit: 
                raise Exception("integer too large, shift: {}".format(shift))
    _di = LEB128_decode

class FromFileMixin:
    @classmethod
    def from_file(cls, filename):
        with open(filename, "rb") as f:
            return cls(f.read())

class VariableReader(FromFileMixin):
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0
        self.size = len(buf)

    def read_int(self):
        (val, nextpos) = _di(self.buf, self.pos)
        self.pos = nextpos
        return val

    def read_bytes_raw(self, size):      
        b = self.buf[self.pos:self.pos+size]
        self.pos += size
        return b

    def read_bytes(self):
        size = self.read_int()
        return self.read_bytes_raw(size)

    def is_end(self):
        return (self.size == self.pos)

class TaggedReader(VariableReader):
    def read_tag(self):
        return (self.read_int(), self.read_bytes())

    def read_all_tags(self, max_tag=3):
        tags = {}
        while (not self.is_end()):
            (tag, bytes) = self.read_tag()
            if (tag > max_tag):
                raise IndexError("tag out of bound: got {}, max {}".format(tag, max_tag))
            tags[tag] = bytes
        return tags

class WideVineSignatureReader(FromFileMixin):
    SIGNER_TAG = 1
    SIGNATURE_TAG = 2
    ISMAINEXE_TAG = 3

    def __init__(self, buf):
        reader = TaggedReader(buf)
        self.version = reader.read_int()
        if (self.version != 0):
            raise Exception("Unsupported signature format version {}".format(self.version))
        self.tags = reader.read_all_tags()

        self.signer = self.tags[self.SIGNER_TAG]
        self.signature = self.tags[self.SIGNATURE_TAG]

        extra = self.tags[self.ISMAINEXE_TAG]
        if (len(extra) != 1 or (extra[0] > 1)):
            raise Exception("Unexpected 'ismainexe' field value (not '\\x00' or '\\x01'), please check: {0}".format(extra))
        
        self.mainexe = bool(extra[0])

    @classmethod
    def get_tags(cls, filename):
        return cls.from_file(filename).tags

device_android_generic = {
    'name': 'android_generic',
    'description': 'android studio cdm',
    'security_level': 3,
    'session_id_type': 'android',
    'private_key_available': True,
    'vmp': False,
    'send_key_control_nonce': True
}
devices_available = [device_android_generic]

FILES_FOLDER = 'devices'

class DeviceConfig:
    def __init__(self, device):
        self.device_name = device['name']
        self.description = device['description']
        self.security_level = device['security_level']
        self.session_id_type = device['session_id_type']
        self.private_key_available = device['private_key_available']
        self.vmp = device['vmp']
        self.send_key_control_nonce = device['send_key_control_nonce']

        if 'keybox_filename' in device:
            self.keybox_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], device['keybox_filename'])
        else:
            self.keybox_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], 'keybox')

        if 'device_cert_filename' in device:
            self.device_cert_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], device['device_cert_filename'])
        else:
            self.device_cert_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], 'device_cert')

        if 'device_private_key_filename' in device:
            self.device_private_key_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], device['device_private_key_filename'])
        else:
            self.device_private_key_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], 'device_private_key')

        if 'device_client_id_blob_filename' in device:
            self.device_client_id_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], device['device_client_id_blob_filename'])
        else:
            self.device_client_id_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], 'device_client_id_blob')

        if 'device_vmp_blob_filename' in device:
            self.device_vmp_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], device['device_vmp_blob_filename'])
        else:
            self.device_vmp_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'], 'device_vmp_blob')

    def __repr__(self):
        return "DeviceConfig(name={}, description={}, security_level={}, session_id_type={}, private_key_available={}, vmp={})".format(self.device_name, self.description, self.security_level, self.session_id_type, self.private_key_available, self.vmp)

class Cdm:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sessions = {}

    def open_session(self, init_data_b64, device, raw_init_data = None, offline=False):
        if device.session_id_type == 'android':
            # format: 16 random hexdigits, 2 digit counter, 14 0s
            rand_ascii = ''.join(random.choice('ABCDEF0123456789') for _ in range(16))
            counter = '01' # this resets regularly so its fine to use 01
            rest = '00000000000000'
            session_id = rand_ascii + counter + rest
            session_id = session_id.encode('ascii')
        elif device.session_id_type == 'chrome':
            rand_bytes = get_random_bytes(16)
            session_id = rand_bytes
        else:
            # other formats NYI
            return 1
        if raw_init_data and isinstance(raw_init_data, (bytes, bytearray)):
            # used for NF key exchange, where they don't provide a valid PSSH
            init_data = raw_init_data
            self.raw_pssh = True
        else:
            init_data = self._parse_init_data(init_data_b64)
            self.raw_pssh = False

        if init_data:
            new_session = Session(session_id, init_data, device, offline)
        else:
            return 1
        self.sessions[session_id] = new_session
        return session_id

    def _parse_init_data(self, init_data_b64):
        parsed_init_data = WidevineCencHeader()
        try:
            parsed_init_data.ParseFromString(base64.b64decode(init_data_b64)[32:])
        except DecodeError:
            try:
                id_bytes = parsed_init_data.ParseFromString(base64.b64decode(init_data_b64)[32:])
            except DecodeError:
                return None
        return parsed_init_data

    def close_session(self, session_id):
        if session_id in self.sessions:
            self.sessions.pop(session_id)
            return 0
        else:
            return 1

    def set_service_certificate(self, session_id, cert_b64):

        if session_id not in self.sessions:
            return 1

        session = self.sessions[session_id]

        message = SignedMessage()

        try:
            message.ParseFromString(base64.b64decode(cert_b64))
        except DecodeError:
            self.logger.error("failed to parse cert as SignedMessage")

        service_certificate = SignedDeviceCertificate()

        if message.Type:
            try:
                service_certificate.ParseFromString(message.Msg)
            except DecodeError:
                return 1
        else:
            try:
                service_certificate.ParseFromString(base64.b64decode(cert_b64))
            except DecodeError:
                return 1

        session.service_certificate = service_certificate
        session.privacy_mode = True

        return 0

    def get_license_request(self, session_id):

        if session_id not in self.sessions:
            return 1

        session = self.sessions[session_id]

        # raw pssh will be treated as bytes and not parsed
        if self.raw_pssh:
            license_request = SignedLicenseRequestRaw()
        else:
            license_request = SignedLicenseRequest()
        client_id = ClientIdentification()

        if not os.path.exists(session.device_config.device_client_id_blob_filename):
            return 1

        with open(session.device_config.device_client_id_blob_filename, "rb") as f:
            try:
                cid_bytes = client_id.ParseFromString(f.read())
            except DecodeError:
                return 1

        if not self.raw_pssh:
            license_request.Type = SignedLicenseRequest.MessageType.Value('LICENSE_REQUEST')
            license_request.Msg.ContentId.CencId.Pssh.CopyFrom(session.init_data)
        else:
            license_request.Type = SignedLicenseRequestRaw.MessageType.Value('LICENSE_REQUEST')
            license_request.Msg.ContentId.CencId.Pssh = session.init_data # bytes

        if session.offline:
           license_type = LicenseType.Value('OFFLINE')
        else:
           license_type = LicenseType.Value('DEFAULT')
        license_request.Msg.ContentId.CencId.LicenseType = license_type
        license_request.Msg.ContentId.CencId.RequestId = session_id
        license_request.Msg.Type = LicenseRequest.RequestType.Value('NEW')
        license_request.Msg.RequestTime = int(time.time())
        license_request.Msg.ProtocolVersion = ProtocolVersion.Value('CURRENT')
        if session.device_config.send_key_control_nonce:
            license_request.Msg.KeyControlNonce = random.randrange(1, 2**31)

        if session.privacy_mode:
            if session.device_config.vmp:
                vmp_hashes = FileHashes()
                with open(session.device_config.device_vmp_blob_filename, "rb") as f:
                    try:
                        vmp_bytes = vmp_hashes.ParseFromString(f.read())
                    except DecodeError:
                        return 1
                client_id._FileHashes.CopyFrom(vmp_hashes)
            cid_aes_key = get_random_bytes(16)
            cid_iv = get_random_bytes(16)

            cid_cipher = AES.new(cid_aes_key, AES.MODE_CBC, cid_iv)

            encrypted_client_id = cid_cipher.encrypt(Padding.pad(client_id.SerializeToString(), 16))

            service_public_key = RSA.importKey(session.service_certificate._DeviceCertificate.PublicKey)

            service_cipher = PKCS1_OAEP.new(service_public_key)

            encrypted_cid_key = service_cipher.encrypt(cid_aes_key)

            encrypted_client_id_proto = EncryptedClientIdentification()

            encrypted_client_id_proto.ServiceId = session.service_certificate._DeviceCertificate.ServiceId
            encrypted_client_id_proto.ServiceCertificateSerialNumber = session.service_certificate._DeviceCertificate.SerialNumber
            encrypted_client_id_proto.EncryptedClientId = encrypted_client_id
            encrypted_client_id_proto.EncryptedClientIdIv = cid_iv
            encrypted_client_id_proto.EncryptedPrivacyKey = encrypted_cid_key

            license_request.Msg.EncryptedClientId.CopyFrom(encrypted_client_id_proto)
        else:
            license_request.Msg.ClientId.CopyFrom(client_id)

        if session.device_config.private_key_available:
             key = RSA.importKey(open(session.device_config.device_private_key_filename).read())
             session.device_key = key
        else:
             return 1


        hash = SHA1.new(license_request.Msg.SerializeToString())
        signature = pss.new(key).sign(hash)

        license_request.Signature = signature

        session.license_request = license_request

        return license_request.SerializeToString()

    def provide_license(self, session_id, license_b64):

        if session_id not in self.sessions:
            return 1

        session = self.sessions[session_id]

        if not session.license_request:
            return 1

        license = SignedLicense()
        try:
            license.ParseFromString(base64.b64decode(license_b64))
        except DecodeError:
            self.logger.error("unable to parse license - check protobufs")
            return 1

        session.license = license

        oaep_cipher = PKCS1_OAEP.new(session.device_key)

        session.session_key = oaep_cipher.decrypt(license.SessionKey)

        lic_req_msg = session.license_request.Msg.SerializeToString()

        enc_key_base = b"ENCRYPTION\000" + lic_req_msg + b"\0\0\0\x80"
        auth_key_base = b"AUTHENTICATION\0" + lic_req_msg + b"\0\0\2\0"

        enc_key = b"\x01" + enc_key_base
        auth_key_1 = b"\x01" + auth_key_base
        auth_key_2 = b"\x02" + auth_key_base
        auth_key_3 = b"\x03" + auth_key_base
        auth_key_4 = b"\x04" + auth_key_base

        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(enc_key)

        enc_cmac_key = cmac_obj.digest()

        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_1)
        auth_cmac_key_1 = cmac_obj.digest()

        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_2)
        auth_cmac_key_2 = cmac_obj.digest()

        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_3)
        auth_cmac_key_3 = cmac_obj.digest()

        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_4)
        auth_cmac_key_4 = cmac_obj.digest()

        auth_cmac_combined_1 = auth_cmac_key_1 + auth_cmac_key_2
        auth_cmac_combined_2 = auth_cmac_key_3 + auth_cmac_key_4

        session.derived_keys['enc'] = enc_cmac_key
        session.derived_keys['auth_1'] = auth_cmac_combined_1
        session.derived_keys['auth_2'] = auth_cmac_combined_2

        lic_hmac = HMAC.new(session.derived_keys['auth_1'], digestmod=SHA256)
        lic_hmac.update(license.Msg.SerializeToString())

        if lic_hmac.digest() != license.Signature:
            with open("original_lic.bin", "wb") as f:
                f.write(base64.b64decode(license_b64))
            with open("parsed_lic.bin", "wb") as f:
                f.write(license.SerializeToString())
        for key in license.Msg.Key:
            if key.Id:
                key_id = key.Id
            else:
                key_id = License.KeyContainer.KeyType.Name(key.Type).encode('utf-8')
            encrypted_key = key.Key
            iv = key.Iv
            type = License.KeyContainer.KeyType.Name(key.Type)

            cipher = AES.new(session.derived_keys['enc'], AES.MODE_CBC, iv=iv)
            decrypted_key = cipher.decrypt(encrypted_key)
            if type == "OPERATOR_SESSION":
                permissions = []
                perms = key._OperatorSessionKeyPermissions
                for (descriptor, value) in perms.ListFields():
                    if value == 1:
                        permissions.append(descriptor.name)
                print(permissions)
            else:
                permissions = []
            session.keys.append(Key(key_id, type, Padding.unpad(decrypted_key, 16), permissions))
        return 0

    def get_keys(self, session_id):
        if session_id in self.sessions:
            return self.sessions[session_id].keys

class WvDecrypt(object):
    WV_SYSTEM_ID = [
     237, 239, 139, 169, 121, 214, 74, 206, 163, 200, 39, 220, 213, 29, 33, 237]

    def __init__(self, init_data_b64, cert_data_b64, device):
        self.init_data_b64 = init_data_b64
        self.cert_data_b64 = cert_data_b64
        self.device = device
        self.cdm = Cdm()

        def check_pssh(pssh_b64):
            pssh = base64.b64decode(pssh_b64)
            if not pssh[12:28] == bytes(self.WV_SYSTEM_ID):
                new_pssh = bytearray([0, 0, 0])
                new_pssh.append(32 + len(pssh))
                new_pssh[4:] = bytearray(b'pssh')
                new_pssh[8:] = [0, 0, 0, 0]
                new_pssh[13:] = self.WV_SYSTEM_ID
                new_pssh[29:] = [0, 0, 0, 0]
                new_pssh[31] = len(pssh)
                new_pssh[32:] = pssh
                return base64.b64encode(new_pssh)
            else:
                return pssh_b64

        self.session = self.cdm.open_session(check_pssh(self.init_data_b64), DeviceConfig(self.device))
        if self.cert_data_b64:
            self.cdm.set_service_certificate(self.session, self.cert_data_b64)

    def log_message(self, msg):
        return '{}'.format(msg)

    def start_process(self):
        keyswvdecrypt = []
        try:
            for key in self.cdm.get_keys(self.session):
                if key.type == 'CONTENT':
                    keyswvdecrypt.append(self.log_message('{}:{}'.format(key.kid.hex(), key.key.hex())))

        except Exception:
            return (
             False, keyswvdecrypt)
        else:
            return (
             True, keyswvdecrypt)

    def get_challenge(self):
        return self.cdm.get_license_request(self.session)

    def update_license(self, license_b64):
        self.cdm.provide_license(self.session, license_b64)
        return True

class PsshExtractor:
    def __init__(self, response_text):
        self.response_text = response_text

    def extract_pssh(self):
        pssh_match = re.search(r'<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed">.*?<cenc:pssh>(.*?)</cenc:pssh>', self.response_text, re.DOTALL)

        if pssh_match:
            return pssh_match.group(1)
        else:
            cenc_default_kid_match = re.search(r'cenc:default_KID="([^"]+)"', self.response_text)
            if cenc_default_kid_match:
                kid = cenc_default_kid_match.group(1)
                array_of_bytes = bytearray(b'\x00\x00\x002pssh\x00\x00\x00\x00')
                array_of_bytes.extend(bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed"))
                array_of_bytes.extend(b'\x00\x00\x00\x12\x12\x10')
                array_of_bytes.extend(bytes.fromhex(str(kid).replace("-", "")))
                pssh = base64.b64encode(bytes.fromhex(array_of_bytes.hex())).decode("utf-8")
                return pssh
            else:
                return None
class KeyExtractor:
    def __init__(self, pssh_value, cert_b64, license_url, headers):
        self.pssh_value = pssh_value
        self.cert_b64 = cert_b64
        self.license_url = license_url
        self.headers = headers

    def get_keys(self):
        wvdecrypt = WvDecrypt(init_data_b64=self.pssh_value, cert_data_b64=self.cert_b64, device=device_android_generic)
        raw_challenge = wvdecrypt.get_challenge()
        data = raw_challenge

        response = requests.post(self.license_url, headers=self.headers, data=data)
        license_b64 = b64encode(response.content)
        wvdecrypt.update_license(license_b64)
        keys = wvdecrypt.start_process()
        return keys

class DataExtractor_DSNP:
    def __init__(self, content):
        self.content = content

    def extract_base64_by_choice(self, choice):
        if self.content:
            matches = [(match[0], re.search(r'base64,(.*)', match[1]).group(1)) for match in re.findall(r'KEYFORMAT="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",KEYFORMATVERSIONS="[^"]+",CHARACTERISTICS="([^"]+)",URI="([^"]+)"', self.content)]
            if matches:
                if 1 <= choice <= len(matches):
                    characteristics, base64_data = matches[choice - 1]
                    return characteristics, base64_data
                else:
                    return None, None
        return None, None

    def get_characteristics_list(self):
        if self.content:
            matches = [(match[0], re.search(r'base64,(.*)', match[1]).group(1)) for match in re.findall(r'KEYFORMAT="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",KEYFORMATVERSIONS="[^"]+",CHARACTERISTICS="([^"]+)",URI="([^"]+)"', self.content)]
            return matches
        return []

def parse_manifest_ism(manifest_url):
    r = requests.get(manifest_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                                                           'Chrome/72.0.3626.121 Safari/537.36'})

    if r.status_code != 200:
        raise Exception(r.text)

    ism = xmltodict.parse(r.text)

    pssh = ism['SmoothStreamingMedia']['Protection']['ProtectionHeader']['#text']

    pr_pssh_dec = base64.b64decode(pssh).decode('utf16')
    pr_pssh_dec = pr_pssh_dec[pr_pssh_dec.index('<'):]
    pr_pssh_xml = xmltodict.parse(pr_pssh_dec)
    kid_hex = base64.b64decode(pr_pssh_xml['WRMHEADER']['DATA']['KID']).hex()
    
    kid = uuid.UUID(kid_hex).bytes_le.hex()

    stream_indices = ism['SmoothStreamingMedia']['StreamIndex']

    # List to store information for each stream
    stream_info_list = []

    # Iterate over each StreamIndex (as it might be a list)
    for stream_info in stream_indices if isinstance(stream_indices, list) else [stream_indices]:
        type_info = stream_info['@Type']

        if type_info in {'video', 'audio'}:
            # Handle the case where there can be multiple QualityLevel elements
            quality_levels = stream_info.get('QualityLevel', [])

            if not isinstance(quality_levels, list):
                quality_levels = [quality_levels]

            for quality_level in quality_levels:
                codec = quality_level.get('@FourCC', 'N/A')
                bitrate = quality_level.get('@Bitrate', 'N/A')
                
                # Additional attributes for video streams
                if type_info == 'video':
                    max_width = quality_level.get('@MaxWidth', 'N/A')
                    max_height = quality_level.get('@MaxHeight', 'N/A')
                    resolution = f"{max_width}x{max_height}"
                else:
                    resolution = 'N/A'
                
                # Additional attributes for audio streams
                language = stream_info.get('@Language', 'N/A')
                track_id = stream_info.get('@AudioTrackId', 'N/A') if type_info == 'audio' else None

                stream_info_list.append({
                    'type': type_info,
                    'codec': codec,
                    'bitrate': bitrate,
                    'resolution': resolution,
                    'language': language,
                    'track_id': track_id
                })

    # PSSH encoding logic in ism
    array_of_bytes = bytearray(b'\x00\x00\x002pssh\x00\x00\x00\x00')
    array_of_bytes.extend(bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed"))
    array_of_bytes.extend(b'\x00\x00\x00\x12\x12\x10')
    array_of_bytes.extend(bytes.fromhex(str(kid).replace("-", "")))

    encoded_string = base64.b64encode(bytes.fromhex(array_of_bytes.hex())).decode("utf-8")

    return kid, stream_info_list, encoded_string

def get_keys_license_cdrm_project(license_url, headers_license, pssh_value):
    formatted_headers = '\n'.join([f'{key}: "{value}"' for key, value in headers_license.items()])

    json_data = {
        'license': license_url,
        'headers': formatted_headers,
        'pssh': pssh_value,
        'buildInfo': '',
        'proxy': '',
        'cache': False,
    }

    response = requests.post('https://cdrm-project.com/wv', json=json_data)
    return response

def get_keys_cache_cdrm_project(pssh_value):
    data = pssh_value
    response = requests.post('https://cdrm-project.com/findpssh', data=data)
    print_keys_cdrm_project(response)
    
def print_keys_cdrm_project(response):
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        li_elements = soup.find('ol').find_all('li')
        for li in li_elements:
            key = li.get_text(strip=True)
            print(f'KEY: {key}')
    else:
        print(f"Error: {response.status_code}")

def extract_pssh_m3u8(content):
    # Use regular expression to extract the Base64-encoded PSSH value
    pssh_match = re.search(r'URI="data:text/plain;base64,([^"]+)"', content)

    if pssh_match:
        pssh_base64 = pssh_match.group(1)
        return pssh_base64

    # If the regex match fails, return None or raise an exception as needed
    return None
