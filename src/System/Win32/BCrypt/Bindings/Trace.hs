module System.Win32.BCrypt.Bindings.Trace
  ( module System.Win32.BCrypt.Bindings.Trace
  , module Reexports
  ) where

import System.Win32.BCrypt.Bindings.Externals as Reexports
  ( BCRYPT_HANDLE, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE )
import qualified System.Win32.BCrypt.Bindings.Externals as B

c_BCryptOpenAlgorithmProvider =
  hookAfter B.c_BCryptOpenAlgorithmProvider $
    putStrLn "BCryptOpenAlgorithmProvider is called"
c_BCryptCloseAlgorithmProvider =
  hookAfter B.c_BCryptCloseAlgorithmProvider $
    putStrLn "BCryptCloseAlgorithmProvider is called"
c_BCryptGetProperty =
  hookAfter B.c_BCryptGetProperty $
    putStrLn "BCryptGetProperty is called"
c_BCryptSetProperty =
  hookAfter B.c_BCryptSetProperty $
    putStrLn "BCryptSetProperty is called"
c_BCryptGenerateSymmetricKey =
  hookAfter B.c_BCryptGenerateSymmetricKey $
    putStrLn "BCryptGenerateSymmetricKey is called"
c_BCryptDestroyKey =
  hookAfter B.c_BCryptDestroyKey $
    putStrLn "BCryptDestroyKey is called"
c_BCryptEncrypt =
  hookAfter B.c_BCryptEncrypt $
    putStrLn "BCryptEncrypt is called"
c_BCryptDecrypt =
  hookAfter B.c_BCryptDecrypt $
    putStrLn "BCryptDecrypt is called"

class Hookable a where
  hookAfter :: a -> IO () -> a

instance Hookable (IO a) where
  hookAfter act hook = do
    result <- act
    hook
    return result

instance Hookable b => Hookable (a -> b) where
  hookAfter f hook a = hookAfter (f a) hook
