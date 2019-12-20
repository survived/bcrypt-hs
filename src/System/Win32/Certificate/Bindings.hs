{-# LANGUAGE CPP #-}
module System.Win32.Certificate.Bindings (module Preferred) where

#if TRACE
import System.Win32.Certificate.Bindings.Trace as Preferred
#else
import System.Win32.Certificate.Bindings.Externals as Preferred
#endif
