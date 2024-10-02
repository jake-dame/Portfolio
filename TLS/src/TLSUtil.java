/*
 * TLSUtil.java
 *
 * Author: Jake Dame
 * Date: 29 Mar 2024
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

/**
 * TLSUtil includes a number of static functions and member variables that
 * provide functionality for establishing a TLS connection, as well as secure
 * encrypted communication over a public network:
 *     <li>
 *         Reading certificates and RSA keys from files and converting them into
 *         objects
 *     </li>
 *     <li>
 *         Generation of Diffie-Hellman keys and shared secret
 *     </li>
 *     <li>
 *         Session key generation and storage using a hash-based KDF
 *     </li>
 *     <li>
 *         Functionality needed to complete a TLS handshake
 *     </li>
 *     <li>
 *         Encryption and decryption of messages
 *     </li>
 * <p>
 * TLSUtil makes use of many different Java libraries useful for cryptographic
 * purposes. The files needed for this program must be generated in a very
 * specific way, including .pem, .der, and .key files. TLSUtil is designed in
 * tandem with the TLSServer and TLSClient classes, and is not drop-in
 * replacement for any kind of TLS operation. Additionally, it does not follow
 * perfectly modern TLS protocol. The Certificate Authority for this program is
 * in-house.
 */
public class TLSUtil
{

    /**
     * Diffie-Hellman generator (from: RFC 3526 --> 2048-bit MODP Group)
     */
    static final BigInteger DH_generator_m = BigInteger.valueOf( 2 );
    /**
     * Diffie-Hellman prime modulus (from: RFC 3526 --> 2048-bit MODP Group)
     */
    static final BigInteger DH_modulus_m   = get_DH_modulus_from_file();

    /**
     * Diffie-Hellman shared secret
     */
    static BigInteger DH_shared_secret_m;

    /* -- Session keys -- */

    /**
     * Server's HMAC key (SHA256)
     */
    static SecretKey server_mac_m;
    /**
     * Server's encryption (AES) key
     */
    static SecretKey server_enc_m;
    /**
     * Server's initialization vector for AES cipher block-chaining
     */
    static IvParameterSpec server_iv_m;

    /**
     * Client's HMAC key (SHA256)
     */
    static SecretKey client_mac_m;
    /**
     * Client's encryption (AES) key
     */
    static SecretKey client_enc_m;
    /**
     * Client's initialization vector for AES cipher block-chaining
     */
    static IvParameterSpec client_iv_m;

    /**
     * A helper function so that I don't have to store the massive string literal
     * Diffie-Hellman modulus because I was afraid of accidentally changning it.
     * Reads the string (which is
     * a single line in a .txt file in the project directory) in one go and
     * constructs a BigInteger object with it.
     *
     * @return The 2048-bit Diffie-Hellman prime modulus from RFC 3526 group 3
     */
    static BigInteger get_DH_modulus_from_file()
    {
        String file_path = "./DH_modulus.txt";

        String modulus_string = "";
        try
        {
            Scanner sc = new Scanner( new File( file_path ) );
            modulus_string = sc.nextLine();
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        return new BigInteger( modulus_string, 16 );
    }

    /**
     * Generate a random number (this happens once per session). For this
     * assignment, the number is 32 bytes.
     *
     * @return A 32-byte nonce
     */
    static byte[] generate_nonce()
    {
        byte[] nonce = new byte[ 32 ];

        SecureRandom csprng = new SecureRandom();

        csprng.nextBytes( nonce );

        return nonce;
    }

    /**
     * @param file_name The path of the .der file to extract the RSA private key from
     * @return The RSA private key
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    static PrivateKey get_RSA_priv( String file_name
    ) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
    {
        FileInputStream stream = new FileInputStream( file_name );

        byte[] RSA_file = stream.readAllBytes();

        PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec( RSA_file );

        KeyFactory key_factory = KeyFactory.getInstance( "RSA" );

        PrivateKey RSA_private_key = key_factory.generatePrivate( key_spec );

        stream.close();

        return RSA_private_key;
    }

    /**
     * @param file_name The name of the .pem file to extract the (signed) RSA
     *                  public key (i.e. certificate) from
     * @return The RSA public key
     * @throws IOException
     * @throws CertificateException
     */
    static Certificate get_RSA_pub( String file_name ) throws IOException, CertificateException
    {
        FileInputStream stream = new FileInputStream( file_name );

        CertificateFactory certificate_factory = CertificateFactory.getInstance( "X.509" );

        Certificate certificate = certificate_factory.generateCertificate( stream );

        stream.close();

        return certificate;
    }

    /**
     * Generates and returns a large, random prime number so that 0 < number < modulus
     *
     * @return The number (i.e. a valid Diffie-Hellman private key)
     */
    static BigInteger generate_DH_priv()
    {
        SecureRandom csprng = new SecureRandom();

        final int DH_MODULUS_SIZE_IN_BITS = 2048;

        return new BigInteger( DH_MODULUS_SIZE_IN_BITS - 1, csprng );
    }

    /**
     * Generates the Diffie-Hellman public key (i.e. "mixture") using the
     * formula:
     * <p>
     * generator^private_key % modulus.
     * </p>
     *
     * @param DH_private_key Your Diffie-Hellman private key
     * @return Your Diffie-Hellman public key
     */
    public static BigInteger generate_DH_pub( BigInteger DH_private_key )
    {
        return DH_generator_m.modPow( DH_private_key, DH_modulus_m );
    }

    /**
     * Generates the Diffie-Hellman shared secret using the
     * formula:
     * <p>
     * senders_public_key^private key % modulus.
     * </p>
     *
     * @param their_DH_pub The sender's Diffie-Hellman public key
     * @param your_DH_priv Your Diffie-Hellman private key
     */
    static void generate_DH_shared_secret( BigInteger their_DH_pub,
                                           BigInteger your_DH_priv )
    {
        DH_shared_secret_m = their_DH_pub.modPow( your_DH_priv, DH_modulus_m );
    }

    /**
     * Utilizing the authentication/digital signature properties of RSA, this
     * function decrypts a sender's message (in this case, the sender's public
     * key (Diffie-Hellman)). If it matches the sender's public key
     * (Diffie-Hellman) -- which would have been sent, un-encrypted in the same
     * message, in this simulation -- then that means that the sender encrypted
     * the message with the correct private key (i.e. exponent), that would
     * provide authenticity in a true RSA scenario.
     *
     * @param enc_signed_DH_pub The sender's encrypted/signed Diffie-Hellman public key
     * @param RSA_pub           The sender's RSA public key (as certificate)
     * @param DH_pub            The sender's Diffie-Hellman public key
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    static void authenticate( byte[] enc_signed_DH_pub,
                              Certificate RSA_pub,
                              BigInteger DH_pub
    ) throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException
    {
        byte[] dec_DH_pub = TLSUtil.decrypt_signed_DH_public_key( enc_signed_DH_pub, RSA_pub.getPublicKey() );

        if ( !Arrays.equals( dec_DH_pub, DH_pub.toByteArray() ) )
        {
            throw new RuntimeException( "authentication failed" );
        }

    }

    /**
     * @param RSA_priv The sender's RSA private (exponent) key (for authentication)
     * @param DH_pub   The sender's Diffie-Hellman public key to "sign"
     * @return An encrypted/signed (using RSA) Diffie-Hellman public key
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    static byte[] sign_and_encrypt_DH_public_key( PrivateKey RSA_priv,
                                                  BigInteger DH_pub
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {

        Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );

        cipher.init( Cipher.ENCRYPT_MODE, RSA_priv );

        return cipher.doFinal( DH_pub.toByteArray() );
    }

    /**
     * A helper function for {@link TLSUtil#authenticate}
     *
     * @param enc_DH_pub The sender's encrypted/signed Diffie-Hellman public key
     * @param RSA_pub    The sender's RSA public key to decrypt with
     * @return The decrypted/signed Diffie-Hellman key
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    private static byte[] decrypt_signed_DH_public_key( byte[] enc_DH_pub,
                                                        PublicKey RSA_pub
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException
    {
        Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );

        cipher.init( Cipher.DECRYPT_MODE, RSA_pub );

        return cipher.doFinal( enc_DH_pub );
    }

    /**
     * @param cert_to_verify The certificate to verify with the certificate authority
     * @param CA_cert        The certificate authority's certificate
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     */
    static void validate_certificate( Certificate cert_to_verify,
                                      Certificate CA_cert
    ) throws CertificateException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException, NoSuchProviderException
    {
        cert_to_verify.verify( CA_cert.getPublicKey() );
    }

    /**
     * Following mutual authentication, the hash-based key derivation function
     * (HKDF) generates the session keys (meaning, for both client and server,
     * the encryption keys, the MAC keys, and the initialization vectors) for
     * the current TLS connection. The initial input keying material for this
     * assignment/HKDF should be the client's nonce (on either side of the
     * connection, since both sides will have access to it at this point).
     *
     * @param input_keying_material Should be the client's nonce
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    static void HKDF( byte[] input_keying_material
    ) throws NoSuchAlgorithmException, InvalidKeyException
    {
        // Convert byte[] to key
        SecretKey input_key = new SecretKeySpec( input_keying_material, "HmacSHA256" );

        // Pseudorandom Function (PRF)
        Mac hmac_object = Mac.getInstance( "HmacSHA256" );
        hmac_object.init( input_key );
        byte[] pseudorandom_key = hmac_object.doFinal( DH_shared_secret_m.toByteArray() );

        // Key derivation sequence, starting with pseudorandom_key
        byte[] server_enc_array = HKDF_expand( pseudorandom_key, "SERVER ENC" );
        server_enc_m = new SecretKeySpec( server_enc_array, "AES" );

        byte[] client_enc_array = HKDF_expand( server_enc_array, "CLIENT ENC" );
        client_enc_m = new SecretKeySpec( client_enc_array, "AES" );

        byte[] server_mac_array = HKDF_expand( client_enc_array, "SERVER MAC" );
        server_mac_m = new SecretKeySpec( server_mac_array, "HmacSHA256" );

        byte[] client_mac_array = HKDF_expand( server_mac_array, "CLIENT MAC" );
        client_mac_m = new SecretKeySpec( client_mac_array, "HmacSHA256" );

        byte[] server_iv_array = HKDF_expand( client_mac_array, "SERVER IV" );
        server_iv_m = new IvParameterSpec( server_iv_array );

        byte[] client_iv_array = HKDF_expand( server_iv_array, "CLIENT IV" );
        client_iv_m = new IvParameterSpec( client_iv_array );
    }

    /**
     * Helper function that performs the function of the {@link TLSUtil#HKDF} "expand" phase
     *
     * @param input_keying_material The input keying material to expand
     * @param label                 The KDF label
     * @return The (first 16 bytes of) the output keying material
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] HKDF_expand( byte[] input_keying_material,
                                       String label
    ) throws NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKey input_key = new SecretKeySpec( input_keying_material, "HmacSHA256" );

        /*
         Append a specific byte to the label as per HKDF specification.
         For this assignment we are using a byte of value 1.
        */
        label += ( char ) 0x01;
        byte[] label_array = label.getBytes( StandardCharsets.UTF_8 );

        Mac hmac_object = Mac.getInstance( "HmacSHA256" );
        hmac_object.init( input_key );
        byte[] output_keying_material = hmac_object.doFinal( label_array );

        // Return first 16 bytes of output_keying_material for this assignment
        return Arrays.copyOf( output_keying_material, 16 );
    }

    /**
     * @param message  The plaintext to encrypt
     * @param your_mac The sender's session MAC key
     * @param your_enc The sender's session encryption key
     * @param your_iv  The sender's session initialization vector
     * @return The encrypted plaintext message as ciphertext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    static byte[] encrypt( byte[] message,
                           SecretKey your_mac,
                           SecretKey your_enc,
                           IvParameterSpec your_iv
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException
    {
        // Compute HMAC
        Mac hmac_object = Mac.getInstance( "HmacSHA256" );
        hmac_object.init( your_mac );
        byte[] hmac = hmac_object.doFinal( message );

        // Concatenate the plaintext with the HMAC
        byte[] plaintext_plus_HMAC = new byte[ message.length + hmac.length ];

        System.arraycopy( message, 0, plaintext_plus_HMAC, 0, message.length );
        System.arraycopy( hmac, 0, plaintext_plus_HMAC, message.length, hmac.length );

        // Encrypt
        Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
        cipher.init( Cipher.ENCRYPT_MODE, your_enc, your_iv );
        byte[] ciphertext = cipher.doFinal( plaintext_plus_HMAC );

        return ciphertext;
    }

    /**
     * @param ciphertext The ciphertext to decrypt
     * @param their_mac  The sender's session MAC key
     * @param their_enc  The sender's session encryption key
     * @param their_iv   The sender's session initialization vector
     * @return The decrypted ciphertext message as plaintext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    static byte[] decrypt( byte[] ciphertext,
                           SecretKey their_mac,
                           SecretKey their_enc,
                           IvParameterSpec their_iv
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException
    {
        // Decrypt
        Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
        cipher.init( Cipher.DECRYPT_MODE, their_enc, their_iv );
        byte[] plaintext_plus_HMAC = cipher.doFinal( ciphertext );

        // Separate the message body from the HMAC
        byte[] message = new byte[ plaintext_plus_HMAC.length - 32 ];
        System.arraycopy( plaintext_plus_HMAC, 0, message, 0, plaintext_plus_HMAC.length - 32 );

        byte[] sent_hmac = new byte[ plaintext_plus_HMAC.length - message.length ];
        System.arraycopy( plaintext_plus_HMAC, plaintext_plus_HMAC.length - 32, sent_hmac, 0, sent_hmac.length );

        // Compute HMAC
        Mac hmac_object = Mac.getInstance( "HmacSHA256" );
        hmac_object.init( their_mac );
        byte[] hmac = hmac_object.doFinal( message );

        // Compare the sent HMAC with the computed HMAC
        if ( ! Arrays.equals( sent_hmac, hmac ) )
        {
            throw new RuntimeException( "HMAC mismatch during decryption" );
        }

        return message;
    }

    /**
     * Concatenates all the byte arrays in the {@link TLSClient#history_m}
     * member representing all the bytes -- in order -- sent over the wire into
     * a single byte array.
     *
     * @param history The {@link TLSClient#history_m} member
     * @return The {@link TLSClient#history_m} member as a single, concatenated byte[]
     */
    static byte[] compile_history( ArrayList<byte[]> history )
    {
        int len = 0;
        for ( byte[] arr : history )
        {
            len += arr.length;
        }

        byte[] compiled_bytes = new byte[ len ];

        int dest_index = 0;
        for ( byte[] arr : history )
        {
            System.arraycopy( arr, 0, compiled_bytes, dest_index, arr.length );
            dest_index += arr.length;
        }

        return compiled_bytes;
    }

}