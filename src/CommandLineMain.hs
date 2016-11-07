import Steganography (doEncrypt, doDecrypt)
import EccKeys (generateKeyPair, SecretKeyPath(..), PublicKeyPath(..))

import System.Console.Command (Commands,Tree(Node),Command,command,withOption,withNonOption,io)
import System.Console.Program (single,showUsage)

import qualified Data.ByteString.Lazy.Char8 as C8
import qualified System.Console.Argument as Argument

myCommands :: Commands IO
myCommands = Node
  (command "steganography" "A program for hiding encrypted content in a PNG image" . io $ putStrLn "No command given, try \"steganography help\"")
  [
    Node encrypt [],
    Node decrypt [],
    Node generateKey [],
    Node help []
  ]

encrypt,decrypt,help :: Command IO
encrypt = command "encrypt" "Encrypt and hide a file into a PNG file. Notice that it will overwrite the image file. SHARED-SECRET-FILE is the key. INT is the complexity of the PRNG function, higher takes longer time and is therefore more secure. INPUT-FILE is the file to be hidden in the image." $ 
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "INPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile ->
                      withOption signatureOption $ \signFile -> io $ doEncrypt image secret loops file (C8.pack salt) pkiFile signFile

decrypt = command "decrypt" "Get data from a PNG file. Both the SHARED-SECRET-FILE and INT has to be the same as when the file was encrypted. OUTPUT-FILE will be overwritten without warning." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "OUTPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile ->
                      withOption signatureOption $ \signFile -> io $ doDecrypt image secret loops file (C8.pack salt) pkiFile signFile

generateKey = command "generateKey" "Generate Curve22519 keys. This will create two files, [filename].public.key and [filename].secret.key. To use these keys [filename].public.key is shared with anyone who wants to encrypt something for you. [filename].secret.key MUST NEVER BE SHARED!" $
  withNonOption (namedFile "FILENAME") $ \filename -> io $ generateKeyPair (SecretKeyPath $ filename ++ ".secret.key", PublicKeyPath $ filename ++ ".public.key")

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