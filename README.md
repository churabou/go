### go
    plainText := []byte("plainText:0QfriiXsHrvggk3TBZ7F1w4cUErSdKhT")
    key := []byte("dl2zJzaguTMNmhI2PWpTvEpGmcwmfMK") //256
    iv := []byte("orbdB7iZEVqGmiNtd")//128

    cbc := new(CBC256)
    cbc.Key = key
    cbc.IV = iv

    chipherText := cbc.EncryptByCBC(plainText)

    chipherTextBase64Encoded := base64.StdEncoding.EncodeToString(chipherText)
  
    fmt.Println("EncryptByCBC base64encoded :",chipherTextBase64Encoded)

    chipherTextBase64Decoded, err := base64.StdEncoding.DecodeString(chipherTextBase64Encoded)
     if err != nil {
         fmt.Println("base64 decoding error:", err)
    }

    decrypted := cbc.DecryptByCBC(chipherTextBase64Decoded)

    fmt.Println("Decrypted plainText:", string(decrypted[:]))
    
### php

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
            
        let aes = try AES(key: aeskey, iv: aesIV) // aes128 -> 256
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
