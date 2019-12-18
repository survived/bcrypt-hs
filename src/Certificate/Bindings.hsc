module Certificate.Bindings where

import Data.Bits       ((.|.))
import Data.Word       (Word32)
import Foreign.C.Types (CChar)
import Foreign.Ptr     (Ptr)

#include <windows.h>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

type DWORD = Word32


-- Store opening and closing

data CERTSTORE = CERTSTORE -- msdn defines it as undefined type
type HCERTSTORE = Ptr CERTSTORE

-- HCERTSTORE CertOpenSystemStoreA(
--   HCRYPTPROV_LEGACY hProv,
--   LPCSTR            szSubsystemProtocol
-- );
foreign import ccall unsafe "CertOpenSystemStoreA"
  c_CertOpenSystemStoreA
    :: Ptr a -- nullptr_t actually
    -> Ptr CChar -- should be "MY\0"
    -> IO HCERTSTORE

-- BOOL CertCloseStore(
--   HCERTSTORE hCertStore,
--   DWORD      dwFlags
-- );
foreign import ccall unsafe "CertCloseStore"
  c_CertCloseStore
    :: HCERTSTORE
    -> DWORD
    -> IO Bool


-- Certificate opening and closing

data CCERT_CONTEXT = CCERT_CONTEXT -- opaque
type PCCERT_CONTEXT = Ptr CCERT_CONTEXT

-- PCCERT_CONTEXT CertFindCertificateInStore(
--   HCERTSTORE     hCertStore,
--   DWORD          dwCertEncodingType,
--   DWORD          dwFindFlags,
--   DWORD          dwFindType,
--   const void*    pvFindPara,
--   PCCERT_CONTEXT pPrevCertContext
-- );
foreign import ccall unsafe "CertFindCertificateInStore"
  c_CertFindCertificateInStore
    :: HCERTSTORE
    -> DWORD
    -> DWORD
    -> DWORD
    -> Ptr a
    -> PCCERT_CONTEXT
    -> IO PCCERT_CONTEXT

allCertEncodings :: DWORD
allCertEncodings = #{const X509_ASN_ENCODING} .|. #{const PKCS_7_ASN_ENCODING}
certFindProperty :: DWORD
certFindProperty = #{const CERT_FIND_PROPERTY}
certFriendlyNamePropId :: DWORD
certFriendlyNamePropId = #{const CERT_FRIENDLY_NAME_PROP_ID}

-- BOOL CertFreeCertificateContext(
--   PCCERT_CONTEXT pCertContext
-- );
foreign import ccall unsafe "CertFreeCertificateContext"
  c_CertFreeCertificateContext
    :: PCCERT_CONTEXT
    -> IO Bool


-- Certificate properties stuff

-- BOOL CertGetCertificateContextProperty(
--   PCCERT_CONTEXT pCertContext,
--   DWORD          dwPropId,
--   void*          pvData,
--   DWORD*         pcbData
-- );
foreign import ccall unsafe "CertGetCertificateContextProperty"
  c_CertGetCertificateContextProperty
    :: PCCERT_CONTEXT
    -> DWORD
    -> Ptr a
    -> Ptr DWORD
    -> IO Bool

-- BOOL CryptAcquireCertificatePrivateKey(
--   PCCERT_CONTEXT                  pCert,
--   DWORD                           dwFlags,
--   void*                           pvParameters,
--   HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey,
--   DWORD*                          pdwKeySpec,
--   BOOL*                           pfCallerFreeProvOrNCryptKey
-- );
foreign import ccall unsafe "CryptAcquireCertificatePrivateKey"
  c_CryptAcquireCertificatePrivateKey
    :: PCCERT_CONTEXT
    -> DWORD
    -> Ptr a
    -> Ptr NCRYPT_KEY_HANDLE
    -> Ptr DWORD
    -> Ptr Bool
    -> IO Bool

acquireOnlyNCryptFlag :: DWORD
acquireOnlyNCryptFlag = #{const CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG}


-- NCrypt keys

data NCRYPT_KEY = NCRYPT_KEY
type NCRYPT_KEY_HANDLE = Ptr NCRYPT_KEY


-- SECURITY_STATUS NCryptFreeObject(
--   NCRYPT_HANDLE hObject
-- );
foreign import ccall unsafe "NCryptFreeObject"
  c_NCryptFreeObject
    :: NCRYPT_KEY_HANDLE
    -> IO DWORD
