{-# LANGUAGE ScopedTypeVariables #-}
module BCrypt.Bindings where

#include <windows.h>
#include <bcrypt.h>

import Foreign
import Foreign.C.String

import System.IO.Unsafe
import System.Win32.Types

type ULONG = Word32
type BCRYPT_ALG_HANDLE = Ptr ()
type NTSTATUS = Word32

foreign import stdcall unsafe "BCryptOpenAlgorithmProvider"
  c_BCryptOpenAlgorithmProvider
    :: Ptr BCRYPT_ALG_HANDLE
    -> LPCWSTR
    -> LPCWSTR
    -> ULONG
    -> IO NTSTATUS

foreign import stdcall unsafe "BCryptCloseAlgorithmProvider"
  c_BCryptCloseAlgorithmProvider
    :: BCRYPT_ALG_HANDLE
    -> ULONG
    -> IO NTSTATUS
