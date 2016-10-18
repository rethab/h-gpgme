{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module TestUtil where

import qualified Data.ByteString as BS
import Data.Maybe (fromJust)
import Test.QuickCheck

alice_pub_fpr :: BS.ByteString
alice_pub_fpr = "EAACEB8A"

bob_pub_fpr :: BS.ByteString
bob_pub_fpr = "6C4FB8F2"

-- Orphan instance here! Because this is only a test, orphans are probably OK.
-- http://stackoverflow.com/a/3081367/350221
instance Arbitrary BS.ByteString where
    arbitrary = fmap BS.pack arbitrary

justAndRight :: Maybe (Either a b) -> Bool
justAndRight = either (const False) (const True) . maybe (Left undefined) id

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
