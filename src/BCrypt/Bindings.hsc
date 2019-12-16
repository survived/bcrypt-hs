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
