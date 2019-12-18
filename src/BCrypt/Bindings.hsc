{-# LANGUAGE ScopedTypeVariables #-}
module BCrypt.Bindings where

#include <windows.h>
#include <bcrypt.h>

import Foreign
import Foreign.C.String

import System.IO.Unsafe
import System.Win32.Types

type ULONG = Word32
type BCRYPT_HANDLE = Ptr ()
type BCRYPT_ALG_HANDLE = Ptr ()
type BCRYPT_KEY_HANDLE = Ptr ()
type NTSTATUS = Int32

-- NTSTATUS BCryptOpenAlgorithmProvider(
--   BCRYPT_ALG_HANDLE *phAlgorithm,
--   LPCWSTR           pszAlgId,
--   LPCWSTR           pszImplementation,
--   ULONG             dwFlags
-- );
foreign import stdcall unsafe "BCryptOpenAlgorithmProvider"
  c_BCryptOpenAlgorithmProvider
    :: Ptr BCRYPT_ALG_HANDLE
    -> LPCWSTR
    -> LPCWSTR
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptCloseAlgorithmProvider(
--   BCRYPT_ALG_HANDLE hAlgorithm,
--   ULONG             dwFlags
-- );
foreign import stdcall unsafe "BCryptCloseAlgorithmProvider"
  c_BCryptCloseAlgorithmProvider
    :: BCRYPT_ALG_HANDLE
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptGetProperty(
--   BCRYPT_HANDLE hObject,
--   LPCWSTR       pszProperty,
--   PUCHAR        pbOutput,
--   ULONG         cbOutput,
--   ULONG         *pcbResult,
--   ULONG         dwFlags
-- );
foreign import stdcall unsafe "BCryptGetProperty"
  c_BCryptGetProperty
    :: BCRYPT_HANDLE
    -> LPCWSTR
    -> PUCHAR
    -> ULONG
    -> Ptr ULONG
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptGenerateSymmetricKey(
--   BCRYPT_ALG_HANDLE hAlgorithm,
--   BCRYPT_KEY_HANDLE *phKey,
--   PUCHAR            pbKeyObject,
--   ULONG             cbKeyObject,
--   PUCHAR            pbSecret,
--   ULONG             cbSecret,
--   ULONG             dwFlags
-- );
foreign import stdcall unsafe "BCryptGenerateSymmetricKey"
  c_BCryptGenerateSymmetricKey
    :: BCRYPT_ALG_HANDLE
    -> Ptr BCRYPT_KEY_HANDLE
    -> PUCHAR
    -> ULONG
    -> PUCHAR
    -> ULONG
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptDestroyKey(
--   BCRYPT_KEY_HANDLE hKey
-- );
foreign import stdcall unsafe "BCryptDestroyKey"
  c_BCryptDestroyKey
    :: BCRYPT_ALG_HANDLE
    -> IO NTSTATUS

-- NTSTATUS BCryptEncrypt(
--   BCRYPT_KEY_HANDLE hKey,
--   PUCHAR            pbInput,
--   ULONG             cbInput,
--   VOID              *pPaddingInfo,
--   PUCHAR            pbIV,
--   ULONG             cbIV,
--   PUCHAR            pbOutput,
--   ULONG             cbOutput,
--   ULONG             *pcbResult,
--   ULONG             dwFlags
-- );
foreign import stdcall unsafe "BCryptEncrypt"
  c_BCryptEncrypt
    :: BCRYPT_KEY_HANDLE
    -> PUCHAR
    -> ULONG
    -> Ptr ()
    -> PUCHAR
    -> ULONG
    -> PUCHAR
    -> ULONG
    -> Ptr ULONG
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptDecrypt(
--   BCRYPT_KEY_HANDLE hKey,
--   PUCHAR            pbInput,
--   ULONG             cbInput,
--   VOID              *pPaddingInfo,
--   PUCHAR            pbIV,
--   ULONG             cbIV,
--   PUCHAR            pbOutput,
--   ULONG             cbOutput,
--   ULONG             *pcbResult,
--   ULONG             dwFlags
-- );
foreign import stdcall unsafe "BCryptDecrypt"
  c_BCryptDecrypt
    :: BCRYPT_KEY_HANDLE
    -> PUCHAR
    -> ULONG
    -> Ptr ()
    -> PUCHAR
    -> ULONG
    -> PUCHAR
    -> ULONG
    -> Ptr ULONG
    -> ULONG
    -> IO NTSTATUS
