module System.Win32.Certificate.Bindings.Trace
  ( module System.Win32.Certificate.Bindings.Trace
  , module Reexports
  ) where

import System.Win32.BCrypt.Bindings.Trace (Hookable(..))
import System.Win32.Certificate.Bindings.Externals as Reexports
  ( DWORD, NCRYPT_KEY_HANDLE, PCCERT_CONTEXT, certFriendlyNamePropId
  , allCertEncodings, certFindProperty, certFriendlyNamePropId
  , acquireOnlyNCryptFlag, noPaddingFlag )
import qualified System.Win32.Certificate.Bindings.Externals as B

c_CertOpenSystemStoreA =
  hookAfter B.c_CertOpenSystemStoreA $ \status ->
    putStrLn $ "c_CertOpenSystemStoreA returned " ++ show status
c_CertCloseStore =
  hookAfter B.c_CertCloseStore $ \status ->
    putStrLn $ "c_CertCloseStore returned " ++ show status
c_CertFindCertificateInStore =
  hookAfter B.c_CertFindCertificateInStore $ \status ->
    putStrLn $ "c_CertFindCertificateInStore returned " ++ show status
c_CertFreeCertificateContext =
  hookAfter B.c_CertFreeCertificateContext $ \status ->
    putStrLn $ "c_CertFreeCertificateContext returned " ++ show status
c_CertGetCertificateContextProperty =
  hookAfter B.c_CertGetCertificateContextProperty $ \status ->
    putStrLn $ "c_CertGetCertificateContextProperty returned " ++ show status
c_CryptAcquireCertificatePrivateKey =
  hookAfter B.c_CryptAcquireCertificatePrivateKey $ \status ->
    putStrLn $ "c_CryptAcquireCertificatePrivateKey returned " ++ show status
c_NCryptFreeObject =
  hookAfter B.c_NCryptFreeObject $ \status ->
    putStrLn $ "c_NCryptFreeObject returned " ++ show status
c_NCryptGetProperty =
  hookAfter B.c_NCryptGetProperty $ \status ->
    putStrLn $ "c_NCryptGetProperty returned " ++ show status
c_NCryptEncrypt =
  hookAfter B.c_NCryptEncrypt $ \status ->
    putStrLn $ "c_NCryptEncrypt returned " ++ show status
