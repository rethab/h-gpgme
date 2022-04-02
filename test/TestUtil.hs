{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module TestUtil where

import qualified Data.ByteString as BS
import Control.Monad (when)
import Data.Maybe (fromJust, fromMaybe)
import Test.QuickCheck
import System.FilePath    ((</>))
import System.Directory   ( getTemporaryDirectory
                          , createDirectoryIfMissing
                          , removeDirectoryRecursive
                          , doesDirectoryExist
                          )


alicePubFpr :: BS.ByteString
alicePubFpr = "EAACEB8A"

bobPubFpr :: BS.ByteString
bobPubFpr = "6C4FB8F2"

-- Orphan instance here! Because this is only a test, orphans are probably OK.
-- http://stackoverflow.com/a/3081367/350221
instance Arbitrary BS.ByteString where
    arbitrary = fmap BS.pack arbitrary

justAndRight :: Maybe (Either a b) -> Bool
justAndRight = either (const False) (const True) . fromMaybe (Left undefined)

fromJustAndRight :: (Show a) => Maybe (Either a b) -> b
fromJustAndRight = fromRight . fromJust

fromRight :: (Show a) => Either a b -> b
fromRight = either (\e -> error $ "not right: " ++ show e) id

fromLeft :: Either e a -> e
fromLeft (Left e) = e
fromLeft _        = error "is not left"

isLeft :: Either a b -> Bool
isLeft (Right _) = False
isLeft (Left _)  = True

createTemporaryTestDir :: String -> IO FilePath
createTemporaryTestDir s = do
  tmpDir <- getTemporaryDirectory >>= \x -> pure $ x </> s
  -- Cleanup tests that failed the last time
  tmpCheck <- doesDirectoryExist tmpDir
  when tmpCheck $ removeDirectoryRecursive tmpDir
  -- Create temporary directory
  createDirectoryIfMissing True tmpDir
  return tmpDir
