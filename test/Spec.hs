{-# LANGUAGE OverloadedStrings #-}

import Control.Monad (forM_, void)
import Control.Monad.Trans.Resource (runResourceT)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as B

import Test.Hspec
import BCrypt
import Certificate (derivedAesFromCertName, CertificateException)

main :: IO ()
main = hspec $ do
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
  around withAes128 $
    describe "AES key handler" $ do
      it "dedicates cipher length" $ \aes -> do
        let plaintextLen = 32
        ciphertextLen <- lookupCipherTextLength aes $ B.replicate plaintextLen 27
        ciphertextLen `shouldBe` fromIntegral plaintextLen
      it "encrypts a block" $ \aes -> do
        let plaintextLen = 32
        ciphertext <- encrypt aes $ B.replicate plaintextLen 27
        B.length ciphertext `shouldBe` plaintextLen
  describe "System certificate storage AES (requires MorjCert)" $ do
    it "Can be created" . io . runResourceT $
      void $ derivedAesFromCertName "MorjCert"
    it "Can fail to be created" $
      runResourceT (derivedAesFromCertName "123123idontexisthahaha") `shouldThrow` certificateException
    it "Encrypts a block" $ io . runResourceT $ do
      (_, aes) <- derivedAesFromCertName "MorjCert"
      let plaintextLen = 16
      ciphertext <- liftIO . encrypt aes $ B.replicate plaintextLen 27
      liftIO $ B.length ciphertext `shouldBe` plaintextLen
    it "Encrypts predictably" . io . runResourceT $ do
      let plaintext = "There's a cat prowling through the streets at night and she's black and her eyes are burning yellow fierce and bright the night "
      (_, aes1) <- derivedAesFromCertName "MorjCert"
      cipher1 <- liftIO . encrypt aes1 $ plaintext
      (_, aes2) <- derivedAesFromCertName "MorjCert"
      cipher2 <- liftIO . encrypt aes2 $ plaintext
      liftIO $ cipher1 `shouldBe` cipher2

-- | Used to restrict ambiguous MonadIO m to unambiguous IO m
io :: IO a -> IO a
io = id

certificateException :: CertificateException -> Bool
certificateException = const True

withAes128 :: (SymmetricKeyHandle -> IO ()) -> IO ()
withAes128 f = runResourceT $ do
  (_, hAlg) <- openSymmetricAlgorithm BCryptAlgAES MsPrimitiveProvider
  (_, hKey) <- generateSymmetricKey hAlg "0123456789abcdef0123456789abcdef"
  liftIO $ f hKey
