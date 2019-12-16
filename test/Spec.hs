import Control.Monad (forM_, void)
import Control.Monad.Trans.Resource (runResourceT)

import Test.Hspec
import BCrypt

main :: IO ()
main = hspec $
  describe "algorithm handler" $
    forM_ [minBound..maxBound] $ \alg ->
      context (show alg) $ it "acquirable"
        (void . runResourceT $ openSymmetricAlgorithm alg MsPrimitiveProvider :: IO ())
