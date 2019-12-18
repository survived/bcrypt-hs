{-# LANGUAGE TypeFamilies, ScopedTypeVariables, FlexibleContexts #-}
module BCrypt
  ( SymmetricAlgorithm(..)
  , AlgorithmImplProvider(..)
  , SymmetricAlgorithmHandler
  , openSymmetricAlgorithm
  , ObjectLengthProp(..)
  , BCryptProperty
  , getAlgorithmProperty
  , SymmetricKeyHandle
  , generateSymmetricKey
  , lookupCipherTextLength
  , encrypt
  , decrypt
  ) where

import Data.ByteString (ByteString, useAsCStringLen, packCStringLen)
import Data.Function (on)
import Data.Word (Word, Word32)
import Control.Arrow (second)
import Control.Monad (join, when, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Resource (MonadResource, ReleaseKey, allocate, register, unprotect)

import Foreign hiding (void)
import Foreign.C.String
import System.Win32.Types

import qualified BCrypt.Bindings as B

-- | Symmetric Encription Algorithm
data SymmetricAlgorithm
  = BCryptAlgRC2
  | BCryptAlgRC4
  | BCryptAlgAES
  | BCryptAlgDES
  | BCryptAlgDESX
  | BCryptAlg3DES
  | BCryptAlg3DES112
  deriving (Enum, Bounded)

instance Show SymmetricAlgorithm where
  show = \case
    BCryptAlgRC2 -> "RC2"
    BCryptAlgRC4 -> "RC4"
    BCryptAlgAES -> "AES"
    BCryptAlgDES -> "DES"
    BCryptAlgDESX -> "DESX"
    BCryptAlg3DES -> "3DES"
    BCryptAlg3DES112 -> "3DES_112"

data AlgorithmImplProvider
  = MsPrimitiveProvider
  | MsPlatformCryptoProvider
  | DefaultProvider

bCryptAlgImplProviderToString :: AlgorithmImplProvider -> Maybe String
bCryptAlgImplProviderToString = \case
  MsPrimitiveProvider -> Just "Microsoft Primitive Provider"
  MsPlatformCryptoProvider -> Just "Microsoft Platform Crypto Provider"
  DefaultProvider -> Nothing

data SymmetricAlgorithmHandler = SymmetricAlgorithmHandler
  { sAlgHandlerAlg      :: SymmetricAlgorithm
  , sAlgHandlerProvider :: AlgorithmImplProvider
  , sAlgHandler         :: B.BCRYPT_ALG_HANDLE
  }

openSymmetricAlgorithm :: MonadResource m => SymmetricAlgorithm -> AlgorithmImplProvider -> m (ReleaseKey, SymmetricAlgorithmHandler)
openSymmetricAlgorithm alg provider =
  second (SymmetricAlgorithmHandler alg provider) <$> allocate openAlgHandler closeAlgHandler
  where
  withCAlg, withCProvider :: (CWString -> IO a) -> IO a
  withCAlg = withCWString (show alg)
  withCProvider = case bCryptAlgImplProviderToString provider of
    Just p -> withCWString p
    Nothing -> ($ nullPtr)

  openAlgHandler :: IO B.BCRYPT_ALG_HANDLE
  openAlgHandler =
    alloca $ \(handler :: Ptr B.BCRYPT_ALG_HANDLE) ->
    withCAlg $ \c_alg ->
    withCProvider $ \c_provider -> do
      status <- B.c_BCryptOpenAlgorithmProvider handler c_alg c_provider 0
      when (status < 0) $
        fail "cannot open alg"
      peek handler

  closeAlgHandler :: B.BCRYPT_ALG_HANDLE -> IO ()
  closeAlgHandler handler = do
    status <- B.c_BCryptCloseAlgorithmProvider handler 0
    when (status < 0) $
      fail "cannot open alg"

class BCryptProperty p where
  type PropertyValue p :: *
  propertyName :: p -> String

data ObjectLengthProp = ObjectLengthProp
instance BCryptProperty ObjectLengthProp where
  type PropertyValue ObjectLengthProp = DWORD
  propertyName _ = "ObjectLength"

getAlgorithmProperty
  :: forall p. (BCryptProperty p, Storable (PropertyValue p))
  => SymmetricAlgorithmHandler -> p -> IO (PropertyValue p)
getAlgorithmProperty handler prop =
  withCWString (propertyName prop) $ \propName ->
  alloca $ \(propValue :: Ptr (PropertyValue p)) ->
  alloca $ \(pcbResult :: Ptr B.ULONG) -> do
    let propSize = fromIntegral $ sizeOf (undefined :: PropertyValue p)
    status <- B.c_BCryptGetProperty
      (sAlgHandler handler)
      propName
      (castPtr propValue)
      propSize
      pcbResult
      0
    when (status < 0) $
      fail $ "cannot retrieve " ++ propertyName prop ++ " property"
    cbResult <- peek pcbResult
    when (propSize /= cbResult) $
      fail "BCryptGetProperty expected output type's and retrieved one's size are not match"
    peek propValue

data SymmetricKeyHandle = SymmetricKeyHandle
  { symmetricKeyAlg :: SymmetricAlgorithm
  , symmetricKeyProv :: AlgorithmImplProvider
  , symmetricKeyHandle :: B.BCRYPT_KEY_HANDLE
  }

generateSymmetricKey :: MonadResource m => SymmetricAlgorithmHandler -> ByteString -> m (ReleaseKey, SymmetricKeyHandle)
generateSymmetricKey alg privateKey = do
  (objectSize :: B.ULONG) <- liftIO $ getAlgorithmProperty alg ObjectLengthProp
  (releaseObject, objectPtr) <- allocate (mallocArray (fromIntegral objectSize)) free
  (releaseKeyHandle, (status, keyHandle)) <- allocate (generateKey objectSize objectPtr) destroyKey
  when (status < 0) $
    fail "cannot generate a symmetric key"
  -- guarantee that everything will be released in the right order:
  release <- register . join $ ((>>) `on` (void . sequenceA)) <$> unprotect releaseKeyHandle <*> unprotect releaseObject
  return (release, SymmetricKeyHandle (sAlgHandlerAlg alg) (sAlgHandlerProvider alg) keyHandle)
  where
  generateKey :: B.ULONG -> PUCHAR -> IO (B.NTSTATUS, B.BCRYPT_KEY_HANDLE)
  generateKey objectSize objectPtr =
    useAsCStringLen privateKey $ \(privateKeyPtr, privateKeyLen) ->
    alloca $ \(keyPtr :: Ptr B.BCRYPT_KEY_HANDLE) -> do
      status <- B.c_BCryptGenerateSymmetricKey
        (sAlgHandler alg)
        keyPtr
        objectPtr
        objectSize
        (castPtr privateKeyPtr)
        (fromIntegral privateKeyLen)
        0
      (,) status <$> peek keyPtr
  destroyKey :: (B.NTSTATUS, B.BCRYPT_KEY_HANDLE) -> IO ()
  destroyKey (status, keyHandle) =
    when (status >= 0) $ do
      destroyStatus <- B.c_BCryptDestroyKey keyHandle
      when (destroyStatus < 0) $
        fail "cannot destroy a symmetric key"

lookupCipherTextLength :: SymmetricKeyHandle -> ByteString -> IO DWORD
lookupCipherTextLength key plaintext =
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
  alloca $ \(cipherLen :: Ptr DWORD) -> do
    status <- B.c_BCryptEncrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                              nullPtr nullPtr 0 nullPtr 0 cipherLen 0
    when (status < 0) $
      fail "can't determinate length of ciphertext"
    peek cipherLen

encrypt :: SymmetricKeyHandle -> ByteString -> IO ByteString
encrypt key plaintext = do
  cipherLen <- lookupCipherTextLength key plaintext
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
    allocaArray (fromIntegral cipherLen) $ \(cipher :: PUCHAR) ->
    alloca $ \cipherLen' -> do
      status <- B.c_BCryptEncrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                                nullPtr nullPtr 0 cipher cipherLen cipherLen' 0
      when (status < 0) $
        fail "can't encrypt data"
      resultCipherLen <- peek cipherLen'
      when (cipherLen /= resultCipherLen) $
        fail "ciphertext length is not what expected"
      packCStringLen (castPtr cipher, fromIntegral cipherLen)

lookupPlainTextLength :: SymmetricKeyHandle -> ByteString -> IO DWORD
lookupPlainTextLength key plaintext =
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
  alloca $ \(cipherLen :: Ptr DWORD) -> do
    status <- B.c_BCryptDecrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                              nullPtr nullPtr 0 nullPtr 0 cipherLen 0
    when (status < 0) $
      fail "can't determinate length of ciphertext"
    peek cipherLen

decrypt :: SymmetricKeyHandle -> ByteString -> IO ByteString
decrypt key plaintext = do
  cipherLen <- lookupPlainTextLength key plaintext
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
    allocaArray (fromIntegral cipherLen) $ \(cipher :: PUCHAR) ->
    alloca $ \cipherLen' -> do
      status <- B.c_BCryptDecrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                                nullPtr nullPtr 0 cipher cipherLen cipherLen' 0
      when (status < 0) $
        fail "can't decrypt data"
      resultCipherLen <- peek cipherLen'
      when (cipherLen /= resultCipherLen) $
        fail "plaintext length is not what expected"
      packCStringLen (castPtr cipher, fromIntegral cipherLen)
