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
  hookAfter B.c_CertOpenSystemStoreA $
    putStrLn "c_CertOpenSystemStoreA is called"
c_CertCloseStore =
  hookAfter B.c_CertCloseStore $
    putStrLn "c_CertCloseStore is called"
c_CertFindCertificateInStore =
  hookAfter B.c_CertFindCertificateInStore $
    putStrLn "c_CertFindCertificateInStore is called"
c_CertFreeCertificateContext =
  hookAfter B.c_CertFreeCertificateContext $
    putStrLn "c_CertFreeCertificateContext is called"
c_CertGetCertificateContextProperty =
  hookAfter B.c_CertGetCertificateContextProperty $
    putStrLn "c_CertGetCertificateContextProperty is called"
c_CryptAcquireCertificatePrivateKey =
  hookAfter B.c_CryptAcquireCertificatePrivateKey $
    putStrLn "c_CryptAcquireCertificatePrivateKey is called"
c_NCryptFreeObject =
  hookAfter B.c_NCryptFreeObject $
    putStrLn "c_NCryptFreeObject is called"
c_NCryptGetProperty =
  hookAfter B.c_NCryptGetProperty $
    putStrLn "c_NCryptGetProperty is called"
c_NCryptEncrypt =
  hookAfter B.c_NCryptEncrypt $
    putStrLn "c_NCryptEncrypt is called"
