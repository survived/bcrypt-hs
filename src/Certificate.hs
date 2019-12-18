{-# LANGUAGE LambdaCase #-}
module Certificate
( getCertByName
, getPrivateKey
, CertificateException
) where

import Control.Exception            (Exception, throw, bracket)
import Control.Monad                (when)
import Control.Monad.IO.Class       (MonadIO, liftIO)
import Control.Monad.Trans.Class    (lift)
import Control.Monad.Trans.Cont     (ContT (..), evalContT)
import Control.Monad.Trans.Resource ( MonadResource, ReleaseKey, register
                                    , allocate, runResourceT, release
                                    )
import Foreign.C.String             (peekCWString, withCString)
import Foreign.Marshal.Alloc        (free, malloc, mallocBytes, allocaBytes, alloca)
import Foreign.Ptr                  (Ptr, nullPtr)
import Foreign.Storable             (peek, poke, Storable)

import Bindings


newtype CertificateException = CertificateException {what :: String}
  deriving (Show)
instance Exception CertificateException


getCertByName :: MonadResource m => String -> m (ReleaseKey, Maybe PCCERT_CONTEXT)
getCertByName name = allocate ( evalContT $ do
    store      <- ContT allocateStore
    retSizePtr <- ContT alloca
    propIdPtr  <- ContT alloca
    lift $ poke propIdPtr certFriendlyNamePropId
    let startCert = nullPtr
    lift $ iterateCertByName startCert store propIdPtr retSizePtr
  )
  freeMaybeCert
  --
  where
    iterateCertByName prevCert store propIdPtr retSizePtr = do
      cert <- c_CertFindCertificateInStore store allCertEncodings 0 certFindProperty propIdPtr prevCert
      if cert == nullPtr
      then return Nothing -- tried all certificates
      else do
        -- query for size
        success <- c_CertGetCertificateContextProperty cert certFriendlyNamePropId nullPtr retSizePtr
        size <- fmap fromIntegral . peek $ retSizePtr
        allocaBytes size $ \propDataPtr -> do
          _ <- c_CertGetCertificateContextProperty cert certFriendlyNamePropId propDataPtr retSizePtr
          certName <- peekCWString propDataPtr
          if certName == name
          then return (Just cert)
          else iterateCertByName cert store propIdPtr retSizePtr
    --
    freeMaybeCert Nothing     = pure ()
    freeMaybeCert (Just cert) = c_CertFreeCertificateContext cert >> pure ()
    --
    allocateStore = bracket ( do
        store <- withCString "MY" (c_CertOpenSystemStoreA nullPtr)
        when (store == nullPtr) (throw $ CertificateException "failed to open certificate store")
        pure store
      )
      (\store -> c_CertCloseStore store 0 >> pure ())


getPrivateKey :: (MonadResource m, MonadIO m)
              => PCCERT_CONTEXT -> m (ReleaseKey, NCRYPT_KEY_HANDLE)
getPrivateKey cert = do
  (keyHandle, releaseRequired) <- liftIO . evalContT $ do
    legacyDwordPtr        <- ContT alloca
    keyReleaseRequiredPtr <- ContT alloca
    keyHandlePtr          <- ContT alloca
    s <- lift $ c_CryptAcquireCertificatePrivateKey cert acquireOnlyNCryptFlag nullPtr keyHandlePtr
                                                    legacyDwordPtr keyReleaseRequiredPtr
    when (s == False) (throw $ CertificateException "Failed to acquire certifcate key")
    keyHandle       <- lift $ peek keyHandlePtr
    releaseRequired <- lift $ peek keyReleaseRequiredPtr
    pure (keyHandle, releaseRequired)
  releaseKey <- register $ if releaseRequired
    then c_NCryptFreeObject >> pure ()
    else pure ()
  return (releaseKey, keyHandle)
