{-# LANGUAGE CPP #-}
module System.Win32.BCrypt.Bindings (module Preferred) where

#if TRACE
import System.Win32.BCrypt.Bindings.Trace as Preferred
#else
import System.Win32.BCrypt.Bindings.Externals as Preferred
#endif
