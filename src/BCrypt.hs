{-# LANGUAGE TypeFamilies, ScopedTypeVariables, FlexibleContexts #-}
module BCrypt
  ( SymmetricAlgorithm(..)
  , BCryptAlgImplProvider(..)
  , SymmetricAlgorithmHandler
  , openSymmetricAlgorithm
  , ObjectLengthProp(..)
  , getAlgorithmProperty
  ) where

import Data.Word (Word, Word32)
import Control.Arrow (second)
import Control.Monad (when)
import Control.Monad.Trans.Resource (MonadResource, ReleaseKey, allocate)

import Foreign
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

data BCryptAlgImplProvider
  = MsPrimitiveProvider
  | MsPlatformCryptoProvider
  | DefaultProvider

bCryptAlgImplProviderToString :: BCryptAlgImplProvider -> Maybe String
bCryptAlgImplProviderToString = \case
  MsPrimitiveProvider -> Just "Microsoft Primitive Provider"
  MsPlatformCryptoProvider -> Just "Microsoft Platform Crypto Provider"
  DefaultProvider -> Nothing

data SymmetricAlgorithmHandler = SymmetricAlgorithmHandler
  { sAlgHandlerAlg      :: SymmetricAlgorithm
  , sAlgHandlerProvider :: BCryptAlgImplProvider
  , sAlgHandler         :: B.BCRYPT_ALG_HANDLE
  }

openSymmetricAlgorithm :: MonadResource m => SymmetricAlgorithm -> BCryptAlgImplProvider -> m (ReleaseKey, SymmetricAlgorithmHandler)
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
