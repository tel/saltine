import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception

import AuthBench
import OneTimeAuthBench
import BoxBench
import SecretBoxBench
import ConstantTimeBench
import HashBench
import RandomBench
import ScalarMultBench
import SignBench
import StreamBench
import PasswordBench
import AES256GCMBench
import ChaCha20Poly1305Bench
import ChaCha20Poly1305IETFBench
import XChaCha20Poly1305Bench

main :: IO ()
main = do
  authKeyToEval <- authEnv
  authKey <- evaluate $ force authKeyToEval

  oneTimeAuthKeyToEval <- oneTimeAuthEnv
  oneTimeAuthKey <- evaluate $ force oneTimeAuthKeyToEval

  boxToEval <- boxEnv
  boxKeys <- evaluate $ force boxToEval

  secretboxKeyToEval <- secretboxEnv
  secretboxKey <- evaluate $ force secretboxKeyToEval

  scmlToEval <- scalarMultEnv
  scml <- evaluate $ force scmlToEval

  signToEval <- signEnv
  signKey <- evaluate $ force signToEval

  streamKeyToEval <- streamEnv
  streamKey <- evaluate $ force streamKeyToEval

  passwordSaltToEval <- passwordEnv
  passwordSalt <- evaluate $ force passwordSaltToEval

  hashKeysToEval <- hashEnv
  hashKeys <- evaluate $ force hashKeysToEval

  aes256GCMKeyToEval <- aes256GCMEnv
  aes256GCMKey <- evaluate $ force aes256GCMKeyToEval

  chaCha20Poly1305KeyToEval <- chaCha20Poly1305Env
  chaCha20Poly1305Key <- evaluate $ force chaCha20Poly1305KeyToEval

  chaCha20Poly1305IETFKeyToEval <- chaCha20Poly1305IETFEnv
  chaCha20Poly1305IETFKey <- evaluate $ force chaCha20Poly1305IETFKeyToEval

  xChaCha20Poly1305KeyToEval <- xChaCha20Poly1305Env
  xChaCha20Poly1305Key <- evaluate $ force xChaCha20Poly1305KeyToEval

  defaultMain [
      benchAuth authKey
    , benchOneTimeAuth oneTimeAuthKey
    , benchBox boxKeys
    , benchSecretbox secretboxKey
    , benchHash hashKeys
    , benchScalarMult scml
    , benchSign signKey
    , benchStream streamKey
    , benchPassword passwordSalt
    , benchComparison
    , benchAes256GCM aes256GCMKey
    , benchChaCha20Poly1305 chaCha20Poly1305Key
    , benchChaCha20Poly1305IETF chaCha20Poly1305IETFKey
    , benchXChaCha20Poly1305 xChaCha20Poly1305Key
    ]
