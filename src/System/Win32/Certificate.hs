{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
module System.Win32.Certificate
  ( getCertByName
  , getCertByHash
  , getPrivateKey
  , getCertificatePrivateData
  , deriveAes
  , derivedAesFromCertName
  , derivedAesFromCertHash
  , CertificateException
  ) where

import System.Win32.BCrypt          (openSymmetricAlgorithm, generateSymmetricKey, setAlgorithmProperty)
import Control.Exception            (Exception, throw, bracket)
import Control.Monad                (when)
import Control.Monad.IO.Class       (MonadIO, liftIO)
import Control.Monad.Trans.Class    (lift)
import Control.Monad.Trans.Cont     (ContT (..), evalContT)
import Control.Monad.Trans.Resource ( MonadResource, ReleaseKey, register
                                    , allocate, runResourceT, release
                                    , MonadThrow
                                    )
import Data.ByteString              (ByteString, pack, useAsCString, packCStringLen)
import Foreign.C.String             (peekCWString, withCString, withCWString)
import Foreign.Marshal.Alloc        (free, malloc, mallocBytes, allocaBytes, alloca)
import Foreign.Ptr                  (Ptr, castPtr, nullPtr)
import Foreign.Storable             (peek, poke, Storable)

import qualified System.Win32.BCrypt as BCrypt

import System.Win32.Certificate.Bindings


newtype CertificateException = CertificateException {what :: String}
  deriving (Show)
instance Exception CertificateException

getCertByHash :: MonadResource m => ByteString -> m (ReleaseKey, Maybe PCCERT_CONTEXT)
getCertByHash hash = flip allocate freeMaybeCert $ evalContT $ do
  store <- ContT allocateStore
  hash  <- ContT $ withByteStringAsBlob hash
  cert  <- lift $ c_CertFindCertificateInStore store allCertEncodings 0 certFindHash (castPtr hash) nullPtr
  return $ if cert == nullPtr
    then Nothing
    else Just cert

-- | Get certificate from system storage by its friendly name property
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
freeMaybeCert :: Maybe PCCERT_CONTEXT -> IO ()
freeMaybeCert Nothing     = pure ()
freeMaybeCert (Just cert) = c_CertFreeCertificateContext cert >> pure ()
    --
allocateStore :: (HCERTSTORE -> IO a) -> IO a
allocateStore = bracket ( do
    store <- withCString "MY" (c_CertOpenStore c_CERT_STORE_PROV_SYSTEM_A 0 nullPtr c_CERT_SYSTEM_STORE_LOCAL_MACHINE . castPtr)
    when (store == nullPtr) (throw $ CertificateException "failed to open certificate store")
    pure store
  )
  (\store -> c_CertCloseStore store 0 >> pure ())


-- | Get private key from certificate
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
    then c_NCryptFreeObject keyHandle >> pure ()
    else pure ()
  return (releaseKey, keyHandle)


-- | Used to derive other keys, especially bcrypt. As there's no way to simply
-- derive a key from certificate, we get a bytestring that is uniquely
-- determined by certificate private keys, and use that as raw bytes.
getCertificatePrivateData :: (MonadResource m, MonadIO m)
                          => PCCERT_CONTEXT -> m ByteString
getCertificatePrivateData cert = do
  (keyRelease, certKey) <- getPrivateKey cert
  keyMaterial <- liftIO . evalContT $ do
    retSizePtr <- ContT alloca
    --
    blockSizePtr :: Ptr DWORD  <- ContT alloca
    propName <- ContT $ withCWString "Block Length"
    status   <- lift $ c_NCryptGetProperty certKey propName blockSizePtr 4 retSizePtr 0
    when (status /= 0) (throw $ CertificateException "Failed to get block size")
    blockSize <- lift $ peek blockSizePtr
    --
    keyMaterialRaw <- ContT . useAsCString . pack . take (fromIntegral blockSize) $ [0,1..]
    status <- lift $ c_NCryptEncrypt certKey keyMaterialRaw blockSize nullPtr
                                     nullPtr 0 retSizePtr noPaddingFlag
    when (status /= 0) (throw $ CertificateException "Failed to query encrypted data size")
    keySize <- lift $ peek retSizePtr
    keyMaterialPtr <- ContT $ allocaBytes (fromIntegral keySize)
    status <- lift $ c_NCryptEncrypt certKey keyMaterialRaw blockSize nullPtr
                                     keyMaterialPtr keySize retSizePtr noPaddingFlag
    when (status /= 0) (throw $ CertificateException "Failed to get key material")
    lift $ packCStringLen (keyMaterialPtr, fromIntegral keySize)
  release keyRelease
  return keyMaterial


-- | Derive AES from any key material. This is used in conjunction with
-- getCertificatePrivateData to derive aes from windows certificates
deriveAes :: (MonadResource m, MonadIO m, MonadThrow m)
          => ByteString -> m (ReleaseKey, BCrypt.SymmetricKeyHandle)
deriveAes keyMaterial = do
  (algRelease, bcryptAlg) <- openSymmetricAlgorithm BCrypt.BCryptAlgAES BCrypt.MsPrimitiveProvider
  liftIO $ setAlgorithmProperty bcryptAlg BCrypt.ChaingModeProp BCrypt.ChainingModeECB
  r <- generateSymmetricKey bcryptAlg keyMaterial
  release algRelease
  return r


-- | A chain of three function above: gets a certificate with given name, and
-- derives an AES key based on certificate's private key
derivedAesFromCertName :: (MonadResource m, MonadIO m, MonadThrow m)
                       => String -> m (ReleaseKey, BCrypt.SymmetricKeyHandle)
derivedAesFromCertName name = do
  (certRelease, mbCert)   <- getCertByName name
  case mbCert of
    Nothing -> throw . CertificateException $ "Can't find certificate in store by name: " ++ name
    Just cert -> do
      certData <- getCertificatePrivateData cert
      r <- deriveAes certData
      release certRelease
      return r

derivedAesFromCertHash :: (MonadResource m, MonadIO m, MonadThrow m)
                       => ByteString -> m (ReleaseKey, BCrypt.SymmetricKeyHandle)
derivedAesFromCertHash hash = do
  (certRelease, mbCert)   <- getCertByHash hash
  case mbCert of
    Nothing -> throw . CertificateException $ "Can't find certificate in store by hash: " ++ show hash
    Just cert -> do
      certData <- getCertificatePrivateData cert
      r <- deriveAes certData
      release certRelease
      return r
