module TestUtil where

import qualified Data.ByteString as BS
import Data.Maybe (fromJust, isJust)
import Test.QuickCheck

instance Arbitrary BS.ByteString where
    arbitrary = fmap BS.pack arbitrary

justAndRight :: Maybe (Either a b) -> Bool
justAndRight = either (const False) (const True) . maybe (Left undefined) id

fromJustAndRight :: Maybe (Either a b) -> b
fromJustAndRight = fromRight . fromJust

fromRight :: Either a b -> b
fromRight = either (error "not right") id
