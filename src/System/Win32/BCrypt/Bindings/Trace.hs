{-# LANGUAGE TypeFamilies #-}
module System.Win32.BCrypt.Bindings.Trace
  ( module System.Win32.BCrypt.Bindings.Trace
  , module Reexports
  ) where

import System.Win32.BCrypt.Bindings.Externals as Reexports
  ( BCRYPT_HANDLE, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE )
import qualified System.Win32.BCrypt.Bindings.Externals as B

c_BCryptOpenAlgorithmProvider =
  hookAfter B.c_BCryptOpenAlgorithmProvider $ \status ->
    putStrLn $ "BCryptOpenAlgorithmProvider returned " ++ show status
c_BCryptCloseAlgorithmProvider =
  hookAfter B.c_BCryptCloseAlgorithmProvider $ \status ->
    putStrLn $ "BCryptCloseAlgorithmProvider returned " ++ show status
c_BCryptGetProperty =
  hookAfter B.c_BCryptGetProperty $ \status ->
    putStrLn $ "BCryptGetProperty returned " ++ show status
c_BCryptSetProperty =
  hookAfter B.c_BCryptSetProperty $ \status ->
    putStrLn $ "BCryptSetProperty returned " ++ show status
c_BCryptGenerateSymmetricKey =
  hookAfter B.c_BCryptGenerateSymmetricKey $ \status ->
    putStrLn $ "BCryptGenerateSymmetricKey returned " ++ show status
c_BCryptDestroyKey =
  hookAfter B.c_BCryptDestroyKey $ \status ->
    putStrLn $ "BCryptDestroyKey returned " ++ show status
c_BCryptEncrypt =
  hookAfter B.c_BCryptEncrypt $ \status ->
    putStrLn $ "BCryptEncrypt returned " ++ show status
c_BCryptDecrypt =
  hookAfter B.c_BCryptDecrypt $ \status ->
    putStrLn $ "BCryptDecrypt returned " ++ show status

class Hookable a where
  type Result a
  hookAfter :: a -> (Result a -> IO ()) -> a

instance Hookable (IO a) where
  type Result (IO a) = a
  hookAfter act hook = do
    result <- act
    hook result
    return result

instance Hookable b => Hookable (a -> b) where
  type Result (a -> b) = Result b
  hookAfter f hook a = hookAfter (f a) hook
