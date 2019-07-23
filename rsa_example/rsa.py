import M2Crypto
import M2Crypto.BN as BN

def generate_keypair_as_pem(key_len, exponent):
    def empty_callback():
        pass

    rsa = M2Crypto.RSA.gen_key(key_len, exponent, empty_callback)
    # Get RSA Public Key in PEM format
    buf = M2Crypto.BIO.MemoryBuffer('')
    rsa.save_pub_key_bio(buf)
    public_key = buf.getvalue()

    # Get Private Key in PEM format
    buf = M2Crypto.BIO.MemoryBuffer('')
    rsa.save_key_bio(buf, None)
    private_key = buf.getvalue() # RSA Private Key
    
    return (public_key, private_key)

def get_data_digest(data):
    msg_digest = M2Crypto.EVP.MessageDigest('sha256')
    msg_digest.update (data)
    digest =  msg_digest.digest()
    return digest

def generate_secure_msg(A_private_key, B_public_key, message):
    padding = M2Crypto.RSA.pkcs1_oaep_padding
    buf = M2Crypto.BIO.MemoryBuffer('')
    buf.write(B_public_key)
    rsa1 = M2Crypto.RSA.load_pub_key_bio(buf)
    cipher_message = rsa1.public_encrypt(message, padding)
    # Use A's private key to sign the 'cipher_message'
    digest1 = get_data_digest(cipher_message)
    rsa2 = M2Crypto.RSA.load_key_string(A_private_key)
    signature = rsa2.sign(digest1, 'sha256')
    return cipher_message, signature

def read_secure_msg(A_public_key, B_private_key, cipher_message, signature):
    try:
        # Use A's public key to verify 'signature'
        buf = M2Crypto.BIO.MemoryBuffer('')
        buf.write(A_public_key)
        rsa3 = M2Crypto.RSA.load_pub_key_bio(buf)                
        # Verify
        digest2 = get_data_digest(cipher_message)
        rsa3.verify(digest2, signature, 'sha256')
        # Use B's private key to decrypt 'cipher_message'
        rsa4 = M2Crypto.RSA.load_key_string(B_private_key)        
        padding = M2Crypto.RSA.pkcs1_oaep_padding
        plaintext_message = rsa4.private_decrypt(cipher_message, padding)
        return plaintext_message
    except Exception as err:        
        print 'Verify Fail:%r'% err
        raise 

if __name__ == '__main__':
    keylen = 1024         # 1024 bits
    exponent = 65537
    padding = M2Crypto.RSA.pkcs1_oaep_padding
    
    # Generate RSA key-pair in PEM files for public key and private key 
    A_pub_key, A_priv_key = generate_keypair_as_pem(keylen, exponent)
    
    # Generate RSA key-pair in PEM files for public key and private key 
    B_pub_key, B_priv_key = generate_keypair_as_pem(keylen, exponent)

    # A is sender, B is receiver
    msg = 'A want to send this message to B'

    # Sender's behavior
    cipher_msg, signature = generate_secure_msg(A_priv_key, B_pub_key, msg)

    # Receiver's behavior
    plain_text = read_secure_msg(A_pub_key, B_priv_key, cipher_msg, signature)
