{-# LANGUAGE OverloadedStrings #-}

import Control.Monad (forM_, void)
import Control.Monad.Trans.Resource (runResourceT)
import Control.Monad.IO.Class (liftIO)

import Test.Hspec
import BCrypt

main :: IO ()
main = hspec $
  describe "algorithm handler" $ do
    forM_ [minBound..maxBound] $ \alg ->
      context (show alg) $ do
        it "acquirable" . io $
          void . runResourceT $ openSymmetricAlgorithm alg MsPrimitiveProvider
        it "retrieves object length" . io . runResourceT $ do
          (_, hAlg) <- openSymmetricAlgorithm alg MsPrimitiveProvider
          _ <- liftIO $ getAlgorithmProperty hAlg ObjectLengthProp
          return ()
    it "produces aes key" . io . runResourceT $ do
      (_, hAlg) <- openSymmetricAlgorithm BCryptAlgAES MsPrimitiveProvider
      _ <- generateSymmetricKey hAlg "0123456789abcdef0123456789abcdef"
      return ()

-- | Used to restrict ambiguous MonadIO m to unambiguous IO m
io :: IO a -> IO a
io = id
