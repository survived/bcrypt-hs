module BCrypt.Symmetric
  ( SymmetricKeyHandle
  , symmetricKeyAlg, symmetricKeyProv, symmetricKeyHandle
  , generateSymmetricKey
  , lookupCipherTextLength
  , encrypt, decrypt
  ) where

import Control.Monad (when, join, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Resource (MonadResource, ReleaseKey, allocate, register, unprotect)
import Data.ByteString (ByteString, useAsCStringLen, packCStringLen)
import Data.Function (on)
import Foreign.Marshal.Alloc (alloca, free)
import Foreign.Marshal.Array (allocaArray, mallocArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import System.Win32.Types (PUCHAR, DWORD)

import BCrypt.Algorithm (AlgorithmImplProvider, SymmetricAlgorithm, SymmetricAlgorithmHandler, sAlgHandler, sAlgHandlerAlg, sAlgHandlerProvider)
import BCrypt.Properties (ObjectLengthProp(..), getAlgorithmProperty)
import BCrypt.Types
import qualified BCrypt.Bindings as B

data SymmetricKeyHandle = SymmetricKeyHandle
  { symmetricKeyAlg :: SymmetricAlgorithm
  , symmetricKeyProv :: AlgorithmImplProvider
  , symmetricKeyHandle :: B.BCRYPT_KEY_HANDLE
  }

generateSymmetricKey :: MonadResource m => SymmetricAlgorithmHandler -> ByteString -> m (ReleaseKey, SymmetricKeyHandle)
generateSymmetricKey alg privateKey = do
  (objectSize :: ULONG) <- liftIO $ getAlgorithmProperty alg ObjectLengthProp
  (releaseObject, objectPtr) <- allocate (mallocArray (fromIntegral objectSize)) free
  (releaseKeyHandle, (status, keyHandle)) <- allocate (generateKey objectSize objectPtr) destroyKey
  validateNTStatus "can't set property" status
  -- guarantee that everything will be released in the right order:
  release <- register =<< ((>>) `on` (void . sequenceA)) <$> unprotect releaseKeyHandle <*> unprotect releaseObject
  return (release, SymmetricKeyHandle (sAlgHandlerAlg alg) (sAlgHandlerProvider alg) keyHandle)
  where
  generateKey :: ULONG -> PUCHAR -> IO (NTSTATUS, B.BCRYPT_KEY_HANDLE)
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
  destroyKey :: (NTSTATUS, B.BCRYPT_KEY_HANDLE) -> IO ()
  destroyKey (status, keyHandle) =
    when (status >= 0) $
      B.c_BCryptDestroyKey keyHandle
        >>= validateNTStatus "cannot destroy a symmetric key"

lookupCipherTextLength :: SymmetricKeyHandle -> ByteString -> IO DWORD
lookupCipherTextLength key plaintext =
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
  alloca $ \(cipherLen :: Ptr DWORD) -> do
    B.c_BCryptEncrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                              nullPtr nullPtr 0 nullPtr 0 cipherLen 0
      >>= validateNTStatus "can't determinate length of ciphertext"
    peek cipherLen

encrypt :: SymmetricKeyHandle -> ByteString -> IO ByteString
encrypt key plaintext = do
  cipherLen <- lookupCipherTextLength key plaintext
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
    allocaArray (fromIntegral cipherLen) $ \(cipher :: PUCHAR) ->
    alloca $ \cipherLen' -> do
      B.c_BCryptEncrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                                nullPtr nullPtr 0 cipher cipherLen cipherLen' 0
        >>= validateNTStatus "can't encrypt data"
      resultCipherLen <- peek cipherLen'
      when (cipherLen /= resultCipherLen) $
        fail "ciphertext length is not what expected"
      packCStringLen (castPtr cipher, fromIntegral cipherLen)

lookupPlainTextLength :: SymmetricKeyHandle -> ByteString -> IO DWORD
lookupPlainTextLength key plaintext =
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
  alloca $ \(cipherLen :: Ptr DWORD) -> do
    B.c_BCryptDecrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                              nullPtr nullPtr 0 nullPtr 0 cipherLen 0
      >>= validateNTStatus "can't determinate length of ciphertext"
    peek cipherLen

decrypt :: SymmetricKeyHandle -> ByteString -> IO ByteString
decrypt key plaintext = do
  cipherLen <- lookupPlainTextLength key plaintext
  useAsCStringLen plaintext $ \(plaintextPtr, plaintextLen) ->
    allocaArray (fromIntegral cipherLen) $ \(cipher :: PUCHAR) ->
    alloca $ \cipherLen' -> do
      B.c_BCryptDecrypt (symmetricKeyHandle key) (castPtr plaintextPtr) (fromIntegral plaintextLen)
                                nullPtr nullPtr 0 cipher cipherLen cipherLen' 0
        >>= validateNTStatus "can't decrypt data"
      resultCipherLen <- peek cipherLen'
      when (cipherLen /= resultCipherLen) $
        fail "plaintext length is not what expected"
      packCStringLen (castPtr cipher, fromIntegral cipherLen)
