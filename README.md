# PhotoEditor
# go


### php

<?php
$plaintext = 'plainText:0QfriiXsHrvggk3TBZ7F1w4cUErSdKhT';
$key = 'dl2zJzaguTMNmhI2PWpTvEpGmcwmfMK';
$iv = "orbdB7iZEVqGmiNt";
$method = 'aes-256-cbc';

$encrypted = openssl_encrypt($plaintext, $method, $key, 0, $iv);
printf("encrypted: %s\n", $encrypted);



$decrypted = openssl_decrypt($encrypted, $method, $key, 0, $iv);
printf("decrypted: %s\n", $decrypted);


### swift (CryptoSwift)

let planeText = "plainText:0QfriiXsHrvggk3TBZ7F1w4cUErSdKhT"

        let aeskey = "dl2zJzaguTMNmhI2PWpTvEpGmcwmfMK"
        let aesIV = "orbdB7iZEVqGmiNt"
        
        
        do {
            
            let aes = try AES(key: aeskey, iv: aesIV) // aes128 -> 256??
            let ciphertext = try aes.encrypt(Array(planeText.utf8))
            
            print("ciphertext: \(ciphertext)")
            let base64ciphertext = NSData(bytes: ciphertext, length: ciphertext.count).base64EncodedString()
            print("bas64ciphertext: \(base64ciphertext)")

            let base64decodeCiphertext = try! base64ciphertext.decryptBase64(cipher: aes)
            
            if let encryptedstring = String(bytes: base64decodeCiphertext, encoding: String.Encoding.utf8) {
                print("decode \(encryptedstring)")
                
            } 
        } catch {
            print(error)
        }
