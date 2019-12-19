{-# LANGUAGE ScopedTypeVariables #-}
module System.Win32.BCrypt.Algorithm
  ( SymmetricAlgorithm(..)
  , AlgorithmImplProvider(..)
  , SymmetricAlgorithmHandler
  , sAlgHandlerAlg
  , sAlgHandlerProvider
  , sAlgHandler
  , openSymmetricAlgorithm
  ) where

import Control.Arrow (second)
import Control.Monad (when)
import Control.Monad.Trans.Resource (MonadResource, ReleaseKey, allocate)

import Foreign (Ptr, nullPtr)
import Foreign.C.String (CWString, withCWString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable (peek)

import System.Win32.BCrypt.Types
import qualified System.Win32.BCrypt.Bindings as B

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
      B.c_BCryptOpenAlgorithmProvider handler c_alg c_provider 0
        >>= validateNTStatus "cannot open alg"
      peek handler

  closeAlgHandler :: B.BCRYPT_ALG_HANDLE -> IO ()
  closeAlgHandler handler =
    B.c_BCryptCloseAlgorithmProvider handler 0
      >>= validateNTStatus "cannot close alg"
