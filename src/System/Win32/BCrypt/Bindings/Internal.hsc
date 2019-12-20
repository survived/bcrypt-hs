{-# LANGUAGE ScopedTypeVariables #-}
module System.Win32.BCrypt.Bindings.Internal where

#include <windows.h>
#include <bcrypt.h>

import Foreign
import Foreign.C.String

import System.IO.Unsafe
import System.Win32.Types

import System.Win32.BCrypt.Types

type BCRYPT_HANDLE = Ptr ()
type BCRYPT_ALG_HANDLE = Ptr ()
type BCRYPT_KEY_HANDLE = Ptr ()

-- NTSTATUS BCryptOpenAlgorithmProvider(
--   BCRYPT_ALG_HANDLE *phAlgorithm,
--   LPCWSTR           pszAlgId,
--   LPCWSTR           pszImplementation,
--   ULONG             dwFlags
-- );
foreign import stdcall "BCryptOpenAlgorithmProvider"
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
foreign import stdcall "BCryptCloseAlgorithmProvider"
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
foreign import stdcall "BCryptGetProperty"
  c_BCryptGetProperty
    :: BCRYPT_HANDLE
    -> LPCWSTR
    -> PUCHAR
    -> ULONG
    -> Ptr ULONG
    -> ULONG
    -> IO NTSTATUS

-- NTSTATUS BCryptSetProperty(
--   BCRYPT_HANDLE hObject,
--   LPCWSTR       pszProperty,
--   PUCHAR        pbInput,
--   ULONG         cbInput,
--   ULONG         dwFlags
-- );
foreign import stdcall "BCryptSetProperty"
  c_BCryptSetProperty
    :: BCRYPT_HANDLE
    -> LPCWSTR
    -> PUCHAR
    -> ULONG
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
foreign import stdcall "BCryptGenerateSymmetricKey"
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
foreign import stdcall "BCryptDestroyKey"
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
foreign import stdcall "BCryptEncrypt"
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
foreign import stdcall "BCryptDecrypt"
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
