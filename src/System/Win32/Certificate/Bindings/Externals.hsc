{-# LANGUAGE RecordWildCards #-}
module System.Win32.Certificate.Bindings.Externals where

import Data.Bits       ((.|.))
import Data.ByteString (ByteString, useAsCStringLen)
import Data.Word       (Word32)
import Foreign         (Storable(..), alloca, castPtr, intPtrToPtr)
import Foreign.C.Types (CChar, CWchar)
import Foreign.Ptr     (Ptr)

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

type DWORD = Word32


-- Store opening and closing

data CERTSTORE = CERTSTORE -- msdn defines it as undefined type
type HCERTSTORE = Ptr CERTSTORE

-- HCERTSTORE WINAPI CertOpenStore(
--   _In_       LPCSTR            lpszStoreProvider,
--   _In_       DWORD             dwMsgAndCertEncodingType,
--   _In_       HCRYPTPROV_LEGACY hCryptProv,
--   _In_       DWORD             dwFlags,
--   _In_ const void              *pvPara
-- );
foreign import stdcall unsafe "CertOpenStore"
  c_CertOpenStore
    :: Ptr CChar
    -> DWORD  -- always zero in our cases
    -> Ptr () -- legacy, always NULL
    -> DWORD
    -> Ptr ()
    -> IO HCERTSTORE

c_CERT_STORE_PROV_SYSTEM_A :: Ptr CChar
c_CERT_STORE_PROV_SYSTEM_A = intPtrToPtr $ #{const CERT_STORE_PROV_SYSTEM_A}
c_CERT_SYSTEM_STORE_LOCAL_MACHINE :: DWORD
c_CERT_SYSTEM_STORE_LOCAL_MACHINE = #{const CERT_SYSTEM_STORE_LOCAL_MACHINE}

-- BOOL CertCloseStore(
--   HCERTSTORE hCertStore,
--   DWORD      dwFlags
-- );
foreign import stdcall "CertCloseStore"
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
foreign import stdcall "CertFindCertificateInStore"
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
certFindHash :: DWORD
certFindHash = #{const CERT_FIND_HASH}

-- BOOL CertFreeCertificateContext(
--   PCCERT_CONTEXT pCertContext
-- );
foreign import stdcall "CertFreeCertificateContext"
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
foreign import stdcall "CertGetCertificateContextProperty"
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
foreign import stdcall "CryptAcquireCertificatePrivateKey"
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

type SECURITY_STATUS = Word32


-- SECURITY_STATUS NCryptFreeObject(
--   NCRYPT_HANDLE hObject
-- );
foreign import stdcall "NCryptFreeObject"
  c_NCryptFreeObject
    :: NCRYPT_KEY_HANDLE
    -> IO SECURITY_STATUS


-- SECURITY_STATUS NCryptGetProperty(
--   NCRYPT_HANDLE hObject,
--   LPCWSTR       pszProperty,
--   PBYTE         pbOutput,
--   DWORD         cbOutput,
--   DWORD*        pcbResult,
--   DWORD         dwFlags
-- );
foreign import stdcall "NCryptGetProperty"
  c_NCryptGetProperty
    :: NCRYPT_KEY_HANDLE
    -> Ptr CWchar
    -> Ptr a
    -> DWORD
    -> Ptr DWORD
    -> DWORD
    -> IO SECURITY_STATUS


-- SECURITY_STATUS NCryptEncrypt(
--   NCRYPT_KEY_HANDLE hKey,
--   PBYTE             pbInput,
--   DWORD             cbInput,
--   VOID*             pPaddingInfo,
--   PBYTE             pbOutput,
--   DWORD             cbOutput,
--   DWORD*            pcbResult,
--   DWORD             dwFlags
-- );
foreign import stdcall "NCryptEncrypt"
  c_NCryptEncrypt
    :: NCRYPT_KEY_HANDLE
    -> Ptr inData
    -> DWORD
    -> Ptr nullptr
    -> Ptr outData
    -> DWORD
    -> Ptr DWORD
    -> DWORD
    -> IO SECURITY_STATUS

noPaddingFlag :: DWORD
noPaddingFlag = #{const NCRYPT_NO_PADDING_FLAG}

data CryptoBlob = CryptoBlob
  { cryptoBlobSize :: DWORD
  , cryptoBlobPtr  :: Ptr ()
  }

instance Storable CryptoBlob where
  alignment _ = #{alignment CRYPT_DATA_BLOB}
  sizeOf _ = #{size CRYPT_DATA_BLOB}
  peek ptr = do
    cryptoBlobSize <- #{peek CRYPT_DATA_BLOB, cbData} ptr
    cryptoBlobPtr  <- #{peek CRYPT_DATA_BLOB, pbData} ptr
    return CryptoBlob {..}
  poke ptr CryptoBlob {..} = do
    #{poke CRYPT_DATA_BLOB, cbData} ptr cryptoBlobSize
    #{poke CRYPT_DATA_BLOB, pbData} ptr cryptoBlobPtr

withByteStringAsBlob :: ByteString -> (Ptr CryptoBlob -> IO a) -> IO a
withByteStringAsBlob bs f =
  useAsCStringLen bs $ \(ptr, len) ->
    alloca $ \blobPtr -> do
      poke blobPtr CryptoBlob { cryptoBlobSize = fromIntegral len, cryptoBlobPtr = castPtr ptr }
      f blobPtr
