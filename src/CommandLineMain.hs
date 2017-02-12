import Steganography (doEncrypt, doDecrypt)
import EccKeys (generateKeyPair, SecretKeyPath(..), PublicKeyPath(..))
import Png.PngContainer (PngImageType(..))
import DummyContainer (DummyContainer(..))

import Control.Monad (when)
import Data.Either (isRight)
import Data.Maybe (isJust, fromJust)
import System.Console.Command (Commands,Tree(Node),Command,command,withOption,withNonOption,io)
import System.Console.Program (single,showUsage)

import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Char8 as LC8
import qualified System.Console.Argument as Argument

myCommands :: Commands IO
myCommands = Node
  (command "steganography" "A program for hiding encrypted content in a PNG image" . io $ putStrLn "No command given, try \"steganography help\"")
  [
    Node encrypt [],
    Node decrypt [],
    Node generateKey [],
    Node dummyEncrypt [],
    Node help []
  ]

lazyReadOrEmpty [] = return LC8.empty
lazyReadOrEmpty filename = LC8.readFile filename

readOrEmpty [] = return C8.empty
readOrEmpty filename = C8.readFile filename

doDryEncrypt' imageFile secretFile loops inputFile salt pkiFile signFile = do
  imageData <- readOrEmpty imageFile
  secretData <- readOrEmpty secretFile
  inputData <- readOrEmpty inputFile
  pkiData <- readOrEmpty pkiFile
  signData <- lazyReadOrEmpty signFile
  encrypted <- doEncrypt imageData DummyContainer secretData loops inputData salt pkiData signData
  case encrypted of
    Left err -> putStrLn $ "Error: " ++ err
    Right encrypted' -> putStrLn $ "Result: " ++ (C8.unpack encrypted')

doEncrypt' imageFile secretFile loops inputFile salt pkiFile signFile fastMode = do
  imageData <- readOrEmpty imageFile
  secretData <- readOrEmpty secretFile
  inputData <- readOrEmpty inputFile
  pkiData <- readOrEmpty pkiFile
  signData <- lazyReadOrEmpty signFile
  encrypted <- doEncrypt imageData (if fastMode then PngImageSpawnerFast else PngImageSpawner) secretData loops inputData salt pkiData signData
  case encrypted of
    Left err -> error err
    Right encrypted' -> C8.writeFile imageFile encrypted'

doDecrypt' imageFile secretFile loops output salt pkiFile signFile = do
  imageData <- readOrEmpty imageFile
  secretData <- readOrEmpty secretFile
  pkiData <- lazyReadOrEmpty pkiFile
  signData <- readOrEmpty signFile
  decrypted <- doDecrypt imageData PngImageSpawner secretData loops salt pkiData signData
  case decrypted of
    Left err -> error err
    Right decrypted' -> C8.writeFile output decrypted'

encrypt,decrypt,help,dummyEncrypt :: Command IO
dummyEncrypt = command "dummy" "Do a dry run encryption which outputs exactly what would have been written to the Steganography container. Options are the same as for 'encrypt', except the image file will not be modified and fast mode is no longer an option." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret ->
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "INPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile ->
                      withOption signatureOption $ \signFile -> io $ doDryEncrypt' image secret loops file (C8.pack salt) pkiFile signFile

encrypt = command "encrypt" "Encrypt and hide a file into a PNG file. Notice that it will overwrite the image file. SHARED-SECRET-FILE is the key. INT is the complexity of the PRNG function, higher takes longer time and is therefore more secure. INPUT-FILE is the file to be hidden in the image." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret ->
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "INPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile ->
                      withOption signatureOption $ \signFile ->
                        withOption fastMode $ \fastMode' -> io $ doEncrypt' image secret loops file (C8.pack salt) pkiFile signFile fastMode'

decrypt = command "decrypt" "Get data from a PNG file. Both the SHARED-SECRET-FILE and INT has to be the same as when the file was encrypted. OUTPUT-FILE will be overwritten without warning." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret ->
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "OUTPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile ->
                      withOption signatureOption $ \signFile -> io $ doDecrypt' image secret loops file (C8.pack salt) pkiFile signFile

generateKey = command "generateKey" "Generate Curve22519 keys. This will create two files, [filename].public.key and [filename].secret.key. To use these keys [filename].public.key is shared with anyone who wants to encrypt something for you. [filename].secret.key MUST NEVER BE SHARED!" $
  withNonOption (namedFile "FILENAME") $ \filename -> io $ generateKeyPair (SecretKeyPath $ filename ++ ".secret.key", PublicKeyPath $ filename ++ ".public.key")

fastMode :: Argument.Option Bool
fastMode = Argument.option ['q'] ["quick"] Argument.boolean False "Quick mode. This will simply write pixels instead of moving them around, which will be quicker but make Steganalysis (detection of hidden data) easier."

namedFile :: String -> Argument.Type FilePath
namedFile name = Argument.Type { Argument.name = name, Argument.parser = Right, Argument.defaultValue = Nothing }

pkiFileOption :: Argument.Option String
pkiFileOption = Argument.option ['p'] ["pki"] Argument.file "" "A PKI key to use for public key cryptography. Public key for encryption and private key for decryption."

signatureOption :: Argument.Option String
signatureOption = Argument.option ['v'] ["signature"] Argument.string "" "A PKI key to use for public key signing. Private key for signing and public key for verifying."

saltOption :: Argument.Option String
saltOption = Argument.option ['s'] ["salt"] Argument.string "" "A salt to be applied to the encryption."

help = command "help" "Show usage info" $ io (showUsage myCommands)

main = single myCommands
