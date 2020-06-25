module System.Win32.BCrypt.Types
  ( ULONG
  , NTSTATUS, validateNTStatus
  , BCryptException (..)
  )
where

import Control.Exception.Safe
import Data.Int (Int32)
import Data.Word (Word32)
import System.Win32.Types (ULONG)
import Text.Printf

type NTSTATUS = Int32

data BCryptException = BCryptException NTSTATUS String
  deriving Typeable

instance Exception BCryptException

instance Show BCryptException where
  show (BCryptException status context) = printf "%s: 0x%08x" context status

validateNTStatus :: MonadThrow m => String -> NTSTATUS -> m ()
validateNTStatus context status
  | status < 0 = throw $ BCryptException status context
  | otherwise  = return ()
