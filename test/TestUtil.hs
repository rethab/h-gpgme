{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module TestUtil where

import qualified Data.ByteString as BS
import Control.Monad (forM_, when)
import Data.Maybe (fromJust, fromMaybe)
import Test.QuickCheck
import System.FilePath    ((</>))
import System.Directory   ( getTemporaryDirectory
                          , createDirectoryIfMissing
                          , removeDirectoryRecursive
                          , doesDirectoryExist
                          , listDirectory
                          , copyFile
                          )
import System.Posix.Files ( getFileStatus
                          , isDirectory
                          , isRegularFile
                          , setFileMode
                          )


alicePubFpr :: BS.ByteString
alicePubFpr = "EAACEB8A"

bobPubFpr :: BS.ByteString
bobPubFpr = "6C4FB8F2"

-- | Alice and Bob protect their secret keys with a passphrase, which can only
-- be supplied through a 'Ctx'. Carol's secret key is unprotected, so she is the
-- one to use for the @encrypt'@ \/ @decrypt'@ shorthands, which build their own
-- context and therefore cannot be given a passphrase callback.
carolPubFpr :: BS.ByteString
carolPubFpr = "D66FC19F59A5C554"

realPersonPubFpr :: BS.ByteString
realPersonPubFpr = "2DA4C89E28F515B4"

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

-- | Copy a gpg homedir, secret keys and all, so that a test can modify it
-- without touching the fixture.
copyGpgHomedir :: FilePath -> FilePath -> IO ()
copyGpgHomedir src dst = do
    createDirectoryIfMissing True dst
    -- gpg refuses to use a homedir that others can read
    setFileMode dst 0o700
    entries <- listDirectory src
    forM_ entries $ \entry -> do
        let from = src </> entry
            to   = dst </> entry
        status <- getFileStatus from
        if isDirectory status
          then copyGpgHomedir from to
          -- Where GnuPG has no /run/user to fall back on (macOS, some
          -- containers) it puts its agent sockets straight into the homedir.
          -- Those are not part of the fixture, and cannot be copied anyway.
          else when (isRegularFile status) $ copyFile from to

createTemporaryTestDir :: String -> IO FilePath
createTemporaryTestDir s = do
  tmpDir <- getTemporaryDirectory >>= \x -> pure $ x </> s
  -- Cleanup tests that failed the last time
  tmpCheck <- doesDirectoryExist tmpDir
  when tmpCheck $ removeDirectoryRecursive tmpDir
  -- Create temporary directory
  createDirectoryIfMissing True tmpDir
  return tmpDir
