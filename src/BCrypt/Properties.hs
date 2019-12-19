{-# LANGUAGE DefaultSignatures, ScopedTypeVariables, TypeFamilies, FlexibleContexts #-}
module BCrypt.Properties
  ( BCryptProperty, PropertyGet, PropertySet
  , ObjectLengthProp(..)
  , ChaingModeProp(..), ChainingMode(..)
  , getAlgorithmProperty
  , setAlgorithmProperty
  ) where

import Control.Monad (when)
import Foreign.C.String (withCWString, withCWStringLen)
import Foreign.C.Types (CWchar)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable, sizeOf, peek, poke)
import System.Win32.Types (PUCHAR, DWORD)

import BCrypt.Algorithm (SymmetricAlgorithmHandler, sAlgHandler)
import BCrypt.Types

import qualified BCrypt.Bindings as B

class BCryptProperty p where
  type PropertyValue p :: *
  propertyName :: p -> String

class BCryptProperty p => PropertyGet p where
  marshalBackward :: p -> PUCHAR -> ULONG -> IO (PropertyValue p)
  default marshalBackward :: Storable (PropertyValue p) => p -> PUCHAR -> ULONG -> IO (PropertyValue p)
  marshalBackward _ ptr size = do
    when (fromIntegral size /= sizeOf (undefined :: PropertyValue p)) $
      fail "property value has invalid size"
    peek (castPtr ptr)

class BCryptProperty p => PropertySet p where
  marshalForward  :: p -> PropertyValue p -> ((PUCHAR, ULONG) -> IO a) -> IO a
  default marshalForward :: Storable (PropertyValue p) => p -> PropertyValue p -> ((PUCHAR, ULONG) -> IO a) -> IO a
  marshalForward _ val f =
    alloca $ \(ptr :: Ptr (PropertyValue p)) -> do
      poke ptr val
      f (castPtr ptr, fromIntegral $ sizeOf val)

-- PROPERTIES

-- | The size, in bytes, of the subobject of a provider
data ObjectLengthProp = ObjectLengthProp

instance BCryptProperty ObjectLengthProp where
  type PropertyValue ObjectLengthProp = DWORD
  propertyName _ = "ObjectLength"
instance PropertyGet ObjectLengthProp

-- | Chaining mode of the encryption algorithm
data ChaingModeProp = ChaingModeProp

data ChainingMode
  = ChainingModeCBC -- ^ Sets the algorithm's chaining mode to cipher block chaining.
  | ChainingModeCCM -- ^ Sets the algorithm's chaining mode to counter with CBC-MAC mode.
  | ChainingModeCFB -- ^ Sets the algorithm's chaining mode to cipher feedback.
  | ChainingModeECB -- ^ Sets the algorithm's chaining mode to electronic codebook.
  | ChainingModeGCM -- ^ Sets the algorithm's chaining mode to Galois/counter mode (GCM)
  | ChainingModeNA  -- ^ The algorithm does not support chaining.

instance Show ChainingMode where
  show = \case
    ChainingModeCBC -> "ChainingModeCBC"
    ChainingModeCCM -> "ChainingModeCCM"
    ChainingModeCFB -> "ChainingModeCFB"
    ChainingModeECB -> "ChainingModeECB"
    ChainingModeGCM -> "ChainingModeGCM"
    ChainingModeNA  -> "ChainingModeN/A"

instance BCryptProperty ChaingModeProp where
  type PropertyValue ChaingModeProp = ChainingMode
  propertyName _ = "ChainingMode"

instance PropertySet ChaingModeProp where
  marshalForward _ value f = withCWStringLen (show value) $ \(ptr, len) ->
    f (castPtr ptr, fromIntegral len)

getAlgorithmProperty
  :: (BCryptProperty p, PropertyGet p)
  => SymmetricAlgorithmHandler -> p -> IO (PropertyValue p)
getAlgorithmProperty handler prop =
  withCWString (propertyName prop) $ \propName -> do
    bufSize <- lookupSize propName
    allocaArray (fromIntegral bufSize) $ \valueBuf -> do
      getProp propName valueBuf bufSize
      marshalBackward prop valueBuf bufSize
  where
  lookupSize :: Ptr CWchar -> IO ULONG
  lookupSize propName = alloca $ \(pcbResult :: Ptr ULONG) -> do
    B.c_BCryptGetProperty (sAlgHandler handler) propName nullPtr 0 pcbResult 0
      >>= validateNTStatus "can't determinate length of property value"
    peek pcbResult
  getProp :: Ptr CWchar -> PUCHAR -> ULONG -> IO ()
  getProp propName valueBuf valueBufSize = alloca $ \(pcbResult :: Ptr ULONG) -> do
    B.c_BCryptGetProperty (sAlgHandler handler) propName valueBuf valueBufSize pcbResult 0
      >>= validateNTStatus "can't get property"
    actualBufSize <- peek pcbResult
    when (valueBufSize /= actualBufSize) $
      fail "expected property value size doesn't match actual property value size"
    return ()

setAlgorithmProperty
  :: (BCryptProperty p, PropertySet p)
  => SymmetricAlgorithmHandler -> p -> PropertyValue p -> IO ()
setAlgorithmProperty handler prop propVal =
  withCWString (propertyName prop) $ \propName ->
  marshalForward prop propVal $ \(buf, bufSize) ->
    B.c_BCryptSetProperty (sAlgHandler handler) propName buf bufSize 0
      >>= validateNTStatus "can't set property"
