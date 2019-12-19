{-# LANGUAGE OverloadedStrings #-}

import Control.Exception.Safe (finally)
import Control.Monad (forM_, void)
import Control.Monad.Trans.Resource (runResourceT, unprotect)
import Control.Monad.IO.Class (liftIO)
import Data.Monoid ((<>))
import qualified Data.ByteString as B

import Test.Hspec
import System.Win32.BCrypt
import System.Win32.Certificate (derivedAesFromCertName, CertificateException)

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
    it "produces aes key in ECB mode" . io . runResourceT $ do
      (_, hAlg) <- openSymmetricAlgorithm BCryptAlgAES MsPrimitiveProvider
      liftIO $ setAlgorithmProperty hAlg ChaingModeProp ChainingModeECB
      _ <- generateSymmetricKey hAlg "0123456789abcdef0123456789abcdef"
      return ()
  around withAes128 $
    describe "AES key handler in ECB mode" $ do
      it "dedicates cipher length" $ \aes -> do
        let plaintextLen = 16
        ciphertextLen <- lookupCipherTextLength aes $ B.replicate plaintextLen 27
        ciphertextLen `shouldBe` fromIntegral plaintextLen
      it "encrypts a block" $ \aes -> do
        let plaintextLen = 16
        ciphertext <- encrypt aes $ B.replicate plaintextLen 27
        B.length ciphertext `shouldBe` plaintextLen
      it "decrypts a block" $ \aes -> do
        let plaintextLen = 16
            plaintext = B.replicate plaintextLen 27
        ciphertext <- encrypt aes plaintext
        plaintext' <- decrypt aes ciphertext
        plaintext' `shouldBe` plaintext
      it "doesn't mix blocks" $ \aes -> do
        let block = "1234567890123456"
        let plaintext = block <> block
        ciphertext <- encrypt aes plaintext
        let part1 = B.drop 16 ciphertext
        let part2 = B.take 16 ciphertext
        part1 `shouldBe` part2
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
      ciphertext <- liftIO . encrypt aes1 $ plaintext
      (_, aes2) <- derivedAesFromCertName "MorjCert"
      plaintext' <- liftIO . decrypt aes2 $ ciphertext
      liftIO $ plaintext `shouldBe` plaintext'
    it "doesn't mix blocks" . io . runResourceT $ do
      (_, aes) <- derivedAesFromCertName "MorjCert"
      let block = "1234567890123456"
      let plaintext = block <> block
      ciphertext <- liftIO . encrypt aes $ plaintext
      let part1 = B.drop 16 ciphertext
      let part2 = B.take 16 ciphertext
      liftIO $ part1 `shouldBe` part2
    it "can be got out of resourceT" $ do
      (releaseAction, aes) <- runResourceT $ do
          -- extract them from resourceT as we can't exist inside it
          (key, aes) <- derivedAesFromCertName "MorjCert"
          mbRelease <- unprotect key
          case mbRelease of
            Just key' -> pure (key', aes)
            Nothing -> error "Just created cipher has somehow been released"
      let plaintextLen = 16
      ciphertext <- encrypt aes (B.replicate plaintextLen 27)
        `finally` releaseAction
      B.length ciphertext `shouldBe` plaintextLen
      return ()

-- | Used to restrict ambiguous MonadIO m to unambiguous IO m
io :: IO a -> IO a
io = id

certificateException :: CertificateException -> Bool
certificateException = const True

withAes128 :: (SymmetricKeyHandle -> IO ()) -> IO ()
withAes128 f = runResourceT $ do
  (_, hAlg) <- openSymmetricAlgorithm BCryptAlgAES MsPrimitiveProvider
  liftIO $ setAlgorithmProperty hAlg ChaingModeProp ChainingModeECB
  (_, hKey) <- generateSymmetricKey hAlg "0123456789abcdef0123456789abcdef"
  liftIO $ f hKey
