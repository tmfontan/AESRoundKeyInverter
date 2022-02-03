import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 *  This Class is Responsible for Reversing the Round Key Generation Process in
 *  AES-128bit Encryption in order to Find All of the Previously Generated Round
 *  Keys in Addition to the Original Security 128 bit Security Key used in the
 *  Encryption Process. This Class takes a 32 HEXIDECIMAL Character Round Key as
 *  its Parameter. It then Generates all of the Previous Round Key HEXIDECIMAL
 *  Phrases in Addition to the Original Security Key.
 *
 *  @date October 4, 2020
 *  @author Tyler Fontana
 *  @version 1.0.0
 */
public class InverseKeyGeneration {

    /**
     *  The Array Below Contains All of the HEXIDECIMAL Byte Values used in the
     *  Substitution Step of the Key Generation Process. Depending on the Byte
     *  Passed in as a Parameter, the First HEXIDECIMAL Character in the Byte
     *  will act as the Row Number while the Second HEXIDECIMAL Character will
     *  act as the Column Number in the Table Below. The Byte Value Contained at
     *  the Specified Row and Column Index will be Substituted For the Original
     *  HEXIDECIMAL Byte Passed in as A Parameter.
     *
     *///                                                             0            1            2            3            4            5            6            7            8            9            A            B            C            D            E            F
     public static byte[] SUBSITUTION_BOX = {           /* 0 */ (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76,
                                                        /* 1 */ (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0,
                                                        /* 2 */ (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15,
                                                        /* 3 */ (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75,
                                                        /* 4 */ (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84,
                                                        /* 5 */ (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF,
                                                        /* 6 */ (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8,
                                                        /* 7 */ (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2,
                                                        /* 8 */ (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73,
                                                        /* 9 */ (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB,
                                                        /* A */ (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79,
                                                        /* B */ (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08,
                                                        /* C */ (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A,
                                                        /* D */ (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E,
                                                        /* E */ (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF,
                                                        /* F */ (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16};

    /**
     * The Array Below Contains All of the HEXIDECIMAL Byte Values used in the
     * Inverse Substitution Step of the AES-128 Bit Decryption Process. (Note:
     * This Value is not used in this Class due to the Nature of Reversing the
     * Key Generation Process.)
     *
    *///                                                              0            1            2            3            4            5            6            7            8            9            A            B            C            D            E            F
    public static byte[] INVERSE_SUBSITUTION_BOX = {    /* 0 */ (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB,
                                                        /* 1 */ (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB,
                                                        /* 2 */ (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E,
                                                        /* 3 */ (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25,
                                                        /* 4 */ (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92,
                                                        /* 5 */ (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84,
                                                        /* 6 */ (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06,
                                                        /* 7 */ (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B,
                                                        /* 8 */ (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73,
                                                        /* 9 */ (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E,
                                                        /* A */ (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B,
                                                        /* B */ (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4,
                                                        /* C */ (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F,
                                                        /* D */ (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF,
                                                        /* E */ (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
                                                        /* F */ (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D};

    /**
     * This Array Holds All of the Byte Values Associated with the Round
     * Constant Addition Step in the Round Key Generation Process. Depending on
     * Which Round The Key Generation Process is Currently on, the Byte Value at
     * the Index Corresponding to the Round Number will be Exclusive Or-ed (XOR)
     * with the First Byte of the Byte Array Created After the Substitution
     * Step. (Note: The First Entry '0x8D' acts a Placeholder to Remove the Zero
     * Index and Isn't Used.)
     *////
    public static byte[] ROUND_CONSTANT_BOX = { (byte) 0x8D, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40,
                                                (byte) 0x80, (byte) 0x1B, (byte) 0x36, (byte) 0x6C, (byte) 0xD8, (byte) 0xAB, (byte) 0x4D, (byte) 0x9A,
                                                (byte) 0x2F, (byte) 0x5E, (byte) 0xBC, (byte) 0x63, (byte) 0xC6, (byte) 0x97, (byte) 0x35, (byte) 0x6A,
                                                (byte) 0xD4, (byte) 0xB3, (byte) 0x7D, (byte) 0xFA, (byte) 0xEF, (byte) 0xC5, (byte) 0x91, (byte) 0x39,
                                                (byte) 0x72, (byte) 0xE4, (byte) 0xD3, (byte) 0xBD, (byte) 0x61, (byte) 0xC2, (byte) 0x9F, (byte) 0x25,
                                                (byte) 0x4A, (byte) 0x94, (byte) 0x33, (byte) 0x66, (byte) 0xCC, (byte) 0x83, (byte) 0x1D, (byte) 0x3A,
                                                (byte) 0x74, (byte) 0xE8, (byte) 0xCB, (byte) 0x8D, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
                                                (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1B, (byte) 0x36, (byte) 0x6C, (byte) 0xD8,
                                                (byte) 0xAB, (byte) 0x4D, (byte) 0x9A, (byte) 0x2F, (byte) 0x5E, (byte) 0xBC, (byte) 0x63, (byte) 0xC6,
                                                (byte) 0x97, (byte) 0x35, (byte) 0x6A, (byte) 0xD4, (byte) 0xB3, (byte) 0x7D, (byte) 0xFA, (byte) 0xEF,
                                                (byte) 0xC5, (byte) 0x91, (byte) 0x39, (byte) 0x72, (byte) 0xE4, (byte) 0xD3, (byte) 0xBD, (byte) 0x61,
                                                (byte) 0xC2, (byte) 0x9F, (byte) 0x25, (byte) 0x4A, (byte) 0x94, (byte) 0x33, (byte) 0x66, (byte) 0xCC,
                                                (byte) 0x83, (byte) 0x1D, (byte) 0x3A, (byte) 0x74, (byte) 0xE8, (byte) 0xCB, (byte) 0x8D, (byte) 0x01,
                                                (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1B,
                                                (byte) 0x36, (byte) 0x6C, (byte) 0xD8, (byte) 0xAB, (byte) 0x4D, (byte) 0x9A, (byte) 0x2F, (byte) 0x5E,
                                                (byte) 0xBC, (byte) 0x63, (byte) 0xC6, (byte) 0x97, (byte) 0x35, (byte) 0x6A, (byte) 0xD4, (byte) 0xB3,
                                                (byte) 0x7D, (byte) 0xFA, (byte) 0xEF, (byte) 0xC5, (byte) 0x91, (byte) 0x39, (byte) 0x72, (byte) 0xE4,
                                                (byte) 0xD3, (byte) 0xBD, (byte) 0x61, (byte) 0xC2, (byte) 0x9F, (byte) 0x25, (byte) 0x4A, (byte) 0x94,
                                                (byte) 0x33, (byte) 0x66, (byte) 0xCC, (byte) 0x83, (byte) 0x1D, (byte) 0x3A, (byte) 0x74, (byte) 0xE8,
                                                (byte) 0xCB, (byte) 0x8D, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20,
                                                (byte) 0x40, (byte) 0x80, (byte) 0x1B, (byte) 0x36, (byte) 0x6C, (byte) 0xD8, (byte) 0xAB, (byte) 0x4D,
                                                (byte) 0x9A, (byte) 0x2F, (byte) 0x5E, (byte) 0xBC, (byte) 0x63, (byte) 0xC6, (byte) 0x97, (byte) 0x35,
                                                (byte) 0x6A, (byte) 0xD4, (byte) 0xB3, (byte) 0x7D, (byte) 0xFA, (byte) 0xEF, (byte) 0xC5, (byte) 0x91,
                                                (byte) 0x39, (byte) 0x72, (byte) 0xE4, (byte) 0xD3, (byte) 0xBD, (byte) 0x61, (byte) 0xC2, (byte) 0x9F,
                                                (byte) 0x25, (byte) 0x4A, (byte) 0x94, (byte) 0x33, (byte) 0x66, (byte) 0xCC, (byte) 0x83, (byte) 0x1D,
                                                (byte) 0x3A, (byte) 0x74, (byte) 0xE8, (byte) 0xCB, (byte) 0x8D, (byte) 0x01, (byte) 0x02, (byte) 0x04,
                                                (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1B, (byte) 0x36, (byte) 0x6C,
                                                (byte) 0xD8, (byte) 0xAB, (byte) 0x4D, (byte) 0x9A, (byte) 0x2F, (byte) 0x5E, (byte) 0xBC, (byte) 0x63,
                                                (byte) 0xC6, (byte) 0x97, (byte) 0x35, (byte) 0x6A, (byte) 0xD4, (byte) 0xB3, (byte) 0x7D, (byte) 0xFA,
                                                (byte) 0xEF, (byte) 0xC5, (byte) 0x91, (byte) 0x39, (byte) 0x72, (byte) 0xE4, (byte) 0xD3, (byte) 0xBD,
                                                (byte) 0x61, (byte) 0xC2, (byte) 0x9F, (byte) 0x25, (byte) 0x4A, (byte) 0x94, (byte) 0x33, (byte) 0x66,
                                                (byte) 0xCC, (byte) 0x83, (byte) 0x1D, (byte) 0x3A, (byte) 0x74, (byte) 0xE8, (byte) 0xCB};

    // This Value Contains the Hard Coded Encrypted
    // Message Ciphertext in its Byte Array Form.
    public static byte[] MESSAGE_BYTE_ARRAY = { (byte) 0xE0,  (byte) 0xEC,  (byte) 0xE8,  (byte) 0xBF,  (byte) 0xB0,  (byte) 0xC9,  (byte) 0x85,  (byte) 0x4B,  
                                                (byte) 0xC9,  (byte) 0x91,  (byte) 0x62,  (byte) 0x46,  (byte) 0xDC,  (byte) 0x1E,  (byte) 0x7E,  (byte) 0xC4,  
                                                (byte) 0x29,  (byte) 0x94,  (byte) 0xC7,  (byte) 0x8E,  (byte) 0xBC,  (byte) 0x07,  (byte) 0x96,  (byte) 0x69,  
                                                (byte) 0x0E,  (byte) 0x7E,  (byte) 0x03,  (byte) 0x85,  (byte) 0xFA,  (byte) 0x49,  (byte) 0xEA,  (byte) 0x36,  
                                                (byte) 0x7C,  (byte) 0xD8,  (byte) 0x29,  (byte) 0xE0,  (byte) 0x46,  (byte) 0x53,  (byte) 0x8A,  (byte) 0x20,  
                                                (byte) 0x5A,  (byte) 0x27,  (byte) 0xB6,  (byte) 0x84,  (byte) 0x8E,  (byte) 0x26,  (byte) 0xC2,  (byte) 0x74,  
                                                (byte) 0xFD,  (byte) 0x14,  (byte) 0x94,  (byte) 0xA9,  (byte) 0x30,  (byte) 0xF6,  (byte) 0x4E,  (byte) 0x0E,  
                                                (byte) 0x7B,  (byte) 0xE7,  (byte) 0x0D,  (byte) 0xDC,  (byte) 0xEC,  (byte) 0x6D,  (byte) 0xB9,  (byte) 0xCA,  
                                                (byte) 0xED,  (byte) 0x50,  (byte) 0x5D,  (byte) 0x4E,  (byte) 0x8F,  (byte) 0x77,  (byte) 0x5E,  (byte) 0x4A,  
                                                (byte) 0xB8,  (byte) 0x92,  (byte) 0x0E,  (byte) 0x02,  (byte) 0xB1,  (byte) 0x01,  (byte) 0x08,  (byte) 0x69,  
                                                (byte) 0xA9,  (byte) 0x6E,  (byte) 0xBB,  (byte) 0xB6,  (byte) 0x5B,  (byte) 0x6B,  (byte) 0xA6,  (byte) 0xD7,  
                                                (byte) 0x8A,  (byte) 0x73,  (byte) 0x37,  (byte) 0x35,  (byte) 0xA0,  (byte) 0xD8,  (byte) 0x90,  (byte) 0xD6,  
                                                (byte) 0xAF,  (byte) 0x11,  (byte) 0x58,  (byte) 0x6C,  (byte) 0xB5,  (byte) 0x04,  (byte) 0xFD,  (byte) 0xCA,  
                                                (byte) 0xD9,  (byte) 0x8C,  (byte) 0xB1,  (byte) 0xD1,  (byte) 0xBA,  (byte) 0xF7,  (byte) 0xDA,  (byte) 0x4A,  
                                                (byte) 0x0F,  (byte) 0x20,  (byte) 0x53,  (byte) 0x04,  (byte) 0xD1,  (byte) 0xF7,  (byte) 0x59,  (byte) 0x6A,  
                                                (byte) 0xE2,  (byte) 0x3E,  (byte) 0x94,  (byte) 0x14,  (byte) 0xFD,  (byte) 0x2B,  (byte) 0x56,  (byte) 0x45,  
                                                (byte) 0x8C,  (byte) 0xC1,  (byte) 0x96,  (byte) 0x1C,  (byte) 0x13,  (byte) 0x1C,  (byte) 0x52,  (byte) 0x52,  
                                                (byte) 0x4B,  (byte) 0xF7,  (byte) 0xB2,  (byte) 0xA1,  (byte) 0x51,  (byte) 0x40,  (byte) 0xE9,  (byte) 0x43,  
                                                (byte) 0xD6,  (byte) 0x1A,  (byte) 0xA5,  (byte) 0x3F,  (byte) 0x28,  (byte) 0x03,  (byte) 0x40,  (byte) 0x69,  
                                                (byte) 0x36,  (byte) 0x12,  (byte) 0xF8,  (byte) 0xA9,  (byte) 0x55,  (byte) 0x1D,  (byte) 0x24,  (byte) 0x06,  
                                                (byte) 0xCE,  (byte) 0x6C,  (byte) 0xF6,  (byte) 0x6F,  (byte) 0xCA,  (byte) 0xB6,  (byte) 0xF9,  (byte) 0x25,  
                                                (byte) 0xBD,  (byte) 0x5E,  (byte) 0xB7,  (byte) 0x6C,  (byte) 0xFB,  (byte) 0x25,  (byte) 0x94,  (byte) 0x57,  
                                                (byte) 0x40,  (byte) 0xD2,  (byte) 0x29,  (byte) 0xF0,  (byte) 0xD1,  (byte) 0x25,  (byte) 0xE6,  (byte) 0xDA,  
                                                (byte) 0xDD,  (byte) 0xFA,  (byte) 0x1F,  (byte) 0xAC,  (byte) 0xA4,  (byte) 0x11,  (byte) 0xE9,  (byte) 0x3A,  
                                                (byte) 0xE5,  (byte) 0x6D,  (byte) 0xFD,  (byte) 0x27,  (byte) 0xF1,  (byte) 0x86,  (byte) 0xF3,  (byte) 0x0D,  
                                                (byte) 0xB2,  (byte) 0x2B,  (byte) 0xC7,  (byte) 0x9C,  (byte) 0x17,  (byte) 0x59,  (byte) 0x4F,  (byte) 0x16,  
                                                (byte) 0xFE,  (byte) 0x41,  (byte) 0x45,  (byte) 0x7D,  (byte) 0x2C,  (byte) 0x76,  (byte) 0x9E,  (byte) 0xF0,  
                                                (byte) 0x82,  (byte) 0x01,  (byte) 0xB0,  (byte) 0xFF,  (byte) 0x91,  (byte) 0xD4,  (byte) 0x82,  (byte) 0xBF,  
                                                (byte) 0x92,  (byte) 0xEA,  (byte) 0xA0,  (byte) 0xAE,  (byte) 0xE4,  (byte) 0x99,  (byte) 0x10,  (byte) 0x09,  
                                                (byte) 0xC8,  (byte) 0x71,  (byte) 0x7E,  (byte) 0xFB,  (byte) 0x6D,  (byte) 0xC0,  (byte) 0xCD,  (byte) 0x0B,  
                                                (byte) 0x53,  (byte) 0x5E,  (byte) 0x38,  (byte) 0xEB,  (byte) 0x13,  (byte) 0xEE,  (byte) 0x4A,  (byte) 0xC6,  
                                                (byte) 0x5F,  (byte) 0xCE,  (byte) 0x00,  (byte) 0xE8,  (byte) 0x2C,  (byte) 0x65,  (byte) 0x87,  (byte) 0xFE,  
                                                (byte) 0xCB,  (byte) 0xC9,  (byte) 0xEC,  (byte) 0x55,  (byte) 0x0D,  (byte) 0xDB,  (byte) 0x66,  (byte) 0x58,  
                                                (byte) 0x7D,  (byte) 0x57,  (byte) 0x35,  (byte) 0xB1,  (byte) 0xDB,  (byte) 0x78,  (byte) 0xBF,  (byte) 0xB8,  
                                                (byte) 0xAF,  (byte) 0x54,  (byte) 0xF1,  (byte) 0xF2,  (byte) 0x37,  (byte) 0xD2,  (byte) 0xA2,  (byte) 0xEE,  
                                                (byte) 0xAB,  (byte) 0x2B,  (byte) 0x61,  (byte) 0xD1,  (byte) 0x95,  (byte) 0x10,  (byte) 0x5C,  (byte) 0xBB,  
                                                (byte) 0x65,  (byte) 0x57,  (byte) 0x64,  (byte) 0x4B,  (byte) 0x24,  (byte) 0x74,  (byte) 0xED,  (byte) 0x96,  
                                                (byte) 0xDB,  (byte) 0xB9,  (byte) 0x18,  (byte) 0xDE,  (byte) 0x09,  (byte) 0xD0,  (byte) 0xB1,  (byte) 0x7D,  
                                                (byte) 0xED,  (byte) 0x90,  (byte) 0x1B,  (byte) 0xE6,  (byte) 0x1C,  (byte) 0x97,  (byte) 0xA1,  (byte) 0xCD,  
                                                (byte) 0x3B,  (byte) 0x20,  (byte) 0x0A,  (byte) 0x36,  (byte) 0x78,  (byte) 0x36,  (byte) 0x9F,  (byte) 0xF4 };
    
    // Create New ArrayList which will be used to hold
    // the various HEXIDECIMAL_VALUES_CHAR byte Arrays.
    // This is done to provide an easier Byte to
    // Hexidecimal Conversion Process.
    public static ArrayList<byte[]> HEXIDECIMAL_VALUES_LIST = new ArrayList<>();

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 0.
    public byte[] HEXIDECIMAL_VALUES_CHAR_0 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                                               (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                                               (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                                               (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 1.
    public byte[] HEXIDECIMAL_VALUES_CHAR_1 = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                                               (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                                               (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                                               (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 2.
    public byte[] HEXIDECIMAL_VALUES_CHAR_2 = {(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23,
                                               (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
                                               (byte) 0x28, (byte) 0x29, (byte) 0x2A, (byte) 0x2B,
                                               (byte) 0x2C, (byte) 0x2D, (byte) 0x2E, (byte) 0x2F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 3.
    public byte[] HEXIDECIMAL_VALUES_CHAR_3 = {(byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33,
                                               (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
                                               (byte) 0x38, (byte) 0x39, (byte) 0x3A, (byte) 0x3B,
                                               (byte) 0x3C, (byte) 0x3D, (byte) 0x3E, (byte) 0x3F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 4.
    public byte[] HEXIDECIMAL_VALUES_CHAR_4 = {(byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43,
                                               (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
                                               (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B,
                                               (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 5.
    public byte[] HEXIDECIMAL_VALUES_CHAR_5 = {(byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53,
                                               (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57,
                                               (byte) 0x58, (byte) 0x59, (byte) 0x5A, (byte) 0x5B,
                                               (byte) 0x5C, (byte) 0x5D, (byte) 0x5E, (byte) 0x5F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 6.
    public byte[] HEXIDECIMAL_VALUES_CHAR_6 = {(byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63,
                                               (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67,
                                               (byte) 0x68, (byte) 0x69, (byte) 0x6A, (byte) 0x6B,
                                               (byte) 0x6C, (byte) 0x6D, (byte) 0x6E, (byte) 0x6F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 7.
    public byte[] HEXIDECIMAL_VALUES_CHAR_7 = {(byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73,
                                               (byte) 0x74, (byte) 0x75, (byte) 0x76, (byte) 0x77,
                                               (byte) 0x78, (byte) 0x79, (byte) 0x7A, (byte) 0x7B,
                                               (byte) 0x7C, (byte) 0x7D, (byte) 0x7E, (byte) 0x7F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 8.
    public byte[] HEXIDECIMAL_VALUES_CHAR_8 = {(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
                                               (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
                                               (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B,
                                               (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is 9.
    public byte[] HEXIDECIMAL_VALUES_CHAR_9 = {(byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
                                               (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
                                               (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B,
                                               (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is A.
    public byte[] HEXIDECIMAL_VALUES_CHAR_A = {(byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3,
                                               (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7,
                                               (byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB,
                                               (byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is B.
    public byte[] HEXIDECIMAL_VALUES_CHAR_B = {(byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3,
                                               (byte) 0xB4, (byte) 0xB5, (byte) 0xB6, (byte) 0xB7,
                                               (byte) 0xB8, (byte) 0xB9, (byte) 0xBA, (byte) 0xBB,
                                               (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is C.
    public byte[] HEXIDECIMAL_VALUES_CHAR_C = {(byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3,
                                               (byte) 0xC4, (byte) 0xC5, (byte) 0xC6, (byte) 0xC7,
                                               (byte) 0xC8, (byte) 0xC9, (byte) 0xCA, (byte) 0xCB,
                                               (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is D.
    public byte[] HEXIDECIMAL_VALUES_CHAR_D = {(byte) 0xD0, (byte) 0xD1, (byte) 0xD2, (byte) 0xD3,
                                               (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7,
                                               (byte) 0xD8, (byte) 0xD9, (byte) 0xDA, (byte) 0xDB,
                                               (byte) 0xDC, (byte) 0xDD, (byte) 0xDE, (byte) 0xDF};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is E.
    public byte[] HEXIDECIMAL_VALUES_CHAR_E = {(byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3,
                                               (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7,
                                               (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB,
                                               (byte) 0xEC, (byte) 0xED, (byte) 0xEE, (byte) 0xEF};

    // Create Hexidecimal Byte Array For Bytes Who's
    // First Hexidecimal Character is F.
    public byte[] HEXIDECIMAL_VALUES_CHAR_F = {(byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3,
                                               (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7,
                                               (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
                                               (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF};

    // Create An Arraylist to Hold a List of Our
    // Custom RoundKey Objects
    public static ArrayList<RoundKey> ROUND_KEY_LIST = new ArrayList<>();

    // Variable to Hold the Total Number
    // or Rounds to Be Iterated Through
    // in the Reverse Key Generation Process.
    public static int NUMBER_OF_ROUNDS;
    // The Current Round Number of
    // the Reverse Key Generation Process.
    public static int ROUND_NUMBER;

    // Variable to Hold the User's Inputted
    // Ciphertext String Value.
    public static String CIPHERTEXT_STRING = "";
    // Variable to Hold the User's Inputted
    // Last Round Key.
    public static String ROUNDKEY_STRING = "";

    /**
     *  Basic Constructor That is Used to Add the Char 
     *  Map Byte Array Values to the Global ArrayList 
     *  for Easier Access and Operation Performance.
     *
     */
    public InverseKeyGeneration() {
        // Add the Various Global Byte Array Variables into
        // a single ArrayList to make later operations simpler.
        
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '0' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_0);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '1' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_1);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '2' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_2);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '3' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_3);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '4' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_4);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '5' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_5);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '6' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_6);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '7' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_7);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '8' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_8);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain '9' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_9);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'A' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_A);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'B' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_B);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'C' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_C);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'D' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_D);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'E' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_E);
        // Add the HEXIDECIMAL Byte Values Array Associated With
        // Byte Values that Contain 'F' as thier First Character
        // to the Global ArrayList Variable.
        HEXIDECIMAL_VALUES_LIST.add(HEXIDECIMAL_VALUES_CHAR_F);
    }

    /**
     * This Method is Responsible for Performing the Inverse Key Generation
     * Process on the Current Round Key Passed in as a Parameter. This Method
     * Will Produce the Previous Round Key in the Key Generation Sequence Based
     * on the Bytes Used the the Parameter Byte Array.
     *
     * @param value         The Current Round Key Byte Array.
     *
     * @return              The Byte Array Containing All the 
     *                      Bytes From the Previous Round Key.
     */
    public static byte[] inverseRoundKey(byte[] value) {

        // In these Next Steps, We will create
        // Eight Byte Array Variables which will
        // be used to Divide the Parameter Round
        // Key into Different Segments for
        // Operation Purposes.
        // Holds the First Segment of Four
        // Bytes in the Next (Previous)
        // Round Key.
        byte[] w0 = new byte[4];
        // Holds the Second Segment of Four
        // Bytes in the Next (Previous)
        // Round Key.
        byte[] w1 = new byte[4];
        // Holds the Third Segment of Four
        // Bytes in the Next (Previous)
        // Round Key.
        byte[] w2 = new byte[4];
        // Holds the Forth Segment of Four
        // Bytes in the Next (Previous)
        // Round Key.
        byte[] w3 = new byte[4];
        // Holds the First Segment of Four
        // Bytes in the Parameter
        // Round Key.
        byte[] w4 = new byte[4];
        // Holds the Second Segment of Four
        // Bytes in the Parameter
        // Round Key.
        byte[] w5 = new byte[4];
        // Holds the Third Segment of Four
        // Bytes in the Parameter
        // Round Key.
        byte[] w6 = new byte[4];
        // Holds the Forth Segment of Four
        // Bytes in the Parameter
        // Round Key.
        byte[] w7 = new byte[4];

        // This Byte Array will be Used to
        // Store the Result of the Key
        // Expansion Process Performed
        // on the Byte Array W3.
        byte[] G_w3 = new byte[4];

        // Divide the Parameter Round Key into Four
        // Seperate Segments.
        
        // Store the First Segment of Four Bytes of the Parameter
        // Round Key in the the w4 Byte Array.
        //
        // Store the First Byte of the First Four
        // Byte Segement as the Byte at the First Index
        // in the new Byte Array Value.
        w4[0] = value[0];
        // Store the Second Byte of the First Four
        // Byte Segement as the Byte at the Second Index
        // in the new Byte Array Value.
        w4[1] = value[1];
        // Store the Third Byte of the First Four
        // Byte Segement as the Byte at the Third Index
        // in the new Byte Array Value.
        w4[2] = value[2];
        // Store the Forth Byte of the First Four
        // Byte Segement as the Byte at the Forth Index
        // in the new Byte Array Value.
        w4[3] = value[3];
        
        
        // Store the Second Segment of Four Bytes of the Parameter
        // Round Key in the the w5 Byte Array.
        //
        // Store the First Byte of the Second Four
        // Byte Segement as the Byte at the First Index
        // in the new Byte Array Value.
        w5[0] = value[4];
        // Store the Second Byte of the Second Four
        // Byte Segement as the Byte at the Second Index
        // in the new Byte Array Value.
        w5[1] = value[5];
        // Store the Third Byte of the Second Four
        // Byte Segement as the Byte at the Third Index
        // in the new Byte Array Value.
        w5[2] = value[6];
        // Store the Forth Byte of the Second Four
        // Byte Segement as the Byte at the Forth Index
        // in the new Byte Array Value.
        w5[3] = value[7];
        
        // Store the Third Segment of Four Bytes of the Parameter
        // Round Key in the the w6 Byte Array.
        //
        // Store the First Byte of the Third Four
        // Byte Segement as the Byte at the First Index
        // in the new Byte Array Value.
        w6[0] = value[8];
        // Store the Second Byte of the Third Four
        // Byte Segement as the Byte at the Second Index
        // in the new Byte Array Value.
        w6[1] = value[9];
        // Store the Third Byte of the Third Four
        // Byte Segement as the Byte at the Third Index
        // in the new Byte Array Value.
        w6[2] = value[10];
        // Store the Forth Byte of the Third Four
        // Byte Segement as the Byte at the Forth Index
        // in the new Byte Array Value.
        w6[3] = value[11];
        
        // Store the Forth Segment of Four Bytes of the Parameter
        // Round Key in the the w7 Byte Array.
        //
        // Store the First Byte of the Forth Four
        // Byte Segement as the Byte at the First Index
        // in the new Byte Array Value.
        w7[0] = value[12];
        // Store the Second Byte of the Forth Four
        // Byte Segement as the Byte at the Second Index
        // in the new Byte Array Value.
        w7[1] = value[13];
        // Store the Third Byte of the Forth Four
        // Byte Segement as the Byte at the Third Index
        // in the new Byte Array Value.
        w7[2] = value[14];
        // Store the Forth Byte of the Forth Four
        // Byte Segement as the Byte at the Forth Index
        // in the new Byte Array Value.
        w7[3] = value[15];

        // Get The Second Segment of Four Bytes Contained
        // in the Next (Previous) Round Key By XOR-ing the
        // Corresponding Bytes in the W4 and W5 Byte
        // Arrays. (The First and Second Four Byte Segments
        // of the Current Parameter Round Key.)
        //
        // XOR the First Byte Values From the
        // First and Second Four Byte Segments
        // of the Parameter Array.
        w1[0] = (byte) (w4[0] ^ w5[0]);
        // XOR the Second Byte Values From the
        // First and Second Four Byte Segments
        // of the Parameter Array.
        w1[1] = (byte) (w4[1] ^ w5[1]);
        // XOR the Third Byte Values From the
        // First and Second Four Byte Segments
        // of the Parameter Array.
        w1[2] = (byte) (w4[2] ^ w5[2]);
        // XOR the Forth Byte Values From the
        // First and Second Four Byte Segments
        // of the Parameter Array.
        w1[3] = (byte) (w4[3] ^ w5[3]);

        // Get The Third Segment of Four Bytes Contained
        // in the Next (Previous) Round Key By XOR-ing the
        // Corresponding Bytes in the W5 and W6 Byte
        // Arrays. (The Second and Third Four Byte Segments
        // of the Current Parameter Round Key.)
        //
        // XOR the First Byte Values From the
        // Second and Third Four Byte Segments
        // of the Parameter Array.
        w2[0] = (byte) (w5[0] ^ w6[0]);
        // XOR the Second Byte Values From the
        // Second and Third Four Byte Segments
        // of the Parameter Array.
        w2[1] = (byte) (w5[1] ^ w6[1]);
        // XOR the Third Byte Values From the
        // Second and Third Four Byte Segments
        // of the Parameter Array.
        w2[2] = (byte) (w5[2] ^ w6[2]);
        // XOR the Forth Byte Values From the
        // Second and Third Four Byte Segments
        // of the Parameter Array.
        w2[3] = (byte) (w5[3] ^ w6[3]);

        // Get The Forth Segment of Four Bytes Contained
        // in the Next (Previous) Round Key By XOR-ing the
        // Corresponding Bytes in the W6 and W7 Byte
        // Arrays. (The Third and Forth Four Byte Segments
        // of the Current Parameter Round Key.)
        //
        // XOR the First Byte Values From the
        // Third and Forth Four Byte Segments
        // of the Parameter Array.
        w3[0] = (byte) (w6[0] ^ w7[0]);
        // XOR the Second Byte Values From the
        // Third and Forth Four Byte Segments
        // of the Parameter Array.
        w3[1] = (byte) (w6[1] ^ w7[1]);
        // XOR the Third Byte Values From the
        // Third and Forth Four Byte Segments
        // of the Parameter Array.
        w3[2] = (byte) (w6[2] ^ w7[2]);
        // XOR the Forth Byte Values From the
        // Third and Forth Four Byte Segments
        // of the Parameter Array.
        w3[3] = (byte) (w6[3] ^ w7[3]);

        // In this Next Step, We Mix the
        // Columns of the Forth Four Byte
        // Segment in the Current Parameter
        // Round Key. To do this, we left
        // shift the Bytes Entrys by an
        // Offest of One. These Results are
        // then Stores in the G_w3 Byte Array
        // Seeing as they are the First Step
        // (Mix Columns Step) in the Reverse
        // Key Generation Process.
        //
        // Rotate the Second Byte
        // of the Forth Four Byte
        // Segment in the Parameter
        // Array to the First Position
        // in the New Array.
        // (Left Shift Byte By
        // Offset of 1.)
        G_w3[0] = w3[1];
        // Rotate the Third Byte
        // of the Forth Four Byte
        // Segment in the Parameter
        // Array to the Second Position
        // in the New Array.
        // (Left Shift Byte By
        // Offset of 1.)
        G_w3[1] = w3[2];
        // Rotate the Forth Byte
        // of the Forth Four Byte
        // Segment in the Parameter
        // Array to the Third Position
        // in the New Array.
        // (Left Shift Byte By
        // Offset of 1.)
        G_w3[2] = w3[3];
        // Rotate the First Byte
        // of the Forth Four Byte
        // Segment in the Parameter
        // Array to the Forth Position
        // in the New Array.
        // (Left Shift Byte By
        // Offset of 1.)
        G_w3[3] = w3[0];
        
        // Run the New Byte Array (Key
        // Expansion Array) through the
        // Byte Subitution Step. Set
        // the Returned Array Value
        // as the New Key Expansion
        // Array G_w3.
        G_w3 = substituteBytes(G_w3);
        
        // Run the Subsituted Byte Array
        // Value through the Round Constant
        // Addition Step. Set the Returned
        // Array Value as the New Key
        // Expansion Byte Array G_w3.
        G_w3 = addRoundConstant(G_w3);
        
        // In the Next Step, We will Retrieve
        // the First Four Byte Segement of the
        // Previous Round Key By XOR-ing the
        // Byte Values from the First Four
        // Byte Segment of the Parameter String
        // and the Key Expansion Array we
        // Previously Calculated.
        //
        // Get the First Byte of the Previous
        // Round Key's First Four Byte Segement
        w0[0] = (byte) (w4[0] ^ G_w3[0]);
        // Get the Second Byte of the Previous
        // Round Key's First Four Byte Segement
        w0[1] = (byte) (w4[1] ^ G_w3[1]);
        // Get the Third Byte of the Previous
        // Round Key's First Four Byte Segement
        w0[2] = (byte) (w4[2] ^ G_w3[2]);
        // Get the Forth Byte of the Previous
        // Round Key's First Four Byte Segement
        w0[3] = (byte) (w4[3] ^ G_w3[3]);

        // Create Array Value to Hold the Bytes
        // of the newly found Previous Round Key.
        byte[] previousKey = new byte[16];
        
        // Set the First Byte of the Previous
        // Round Key Byte Array As the First
        // Byte of the W0 Byte Array.
        previousKey[0] = w0[0];   
        // Set the Second Byte of the Previous
        // Round Key Byte Array As the Second
        // Byte of the W0 Byte Array.
        previousKey[1] = w0[1];
        // Set the Third Byte of the Previous
        // Round Key Byte Array As the Third
        // Byte of the W0 Byte Array.
        previousKey[2] = w0[2];     
        // Set the Forth Byte of the Previous
        // Round Key Byte Array As the Forth
        // Byte of the W0 Byte Array.
        previousKey[3] = w0[3];
        // Set the Fifth Byte of the Previous
        // Round Key Byte Array As the First
        // Byte of the W1 Byte Array.
        previousKey[4] = w1[0];      
        // Set the Sixth Byte of the Previous
        // Round Key Byte Array As the Second
        // Byte of the W1 Byte Array.
        previousKey[5] = w1[1];
        // Set the Seventh Byte of the Previous
        // Round Key Byte Array As the Third
        // Byte of the W1 Byte Array.
        previousKey[6] = w1[2];   
        // Set the Eighth Byte of the Previous
        // Round Key Byte Array As the Forth
        // Byte of the W1 Byte Array.
        previousKey[7] = w1[3];
        // Set the Ninth Byte of the Previous
        // Round Key Byte Array As the First
        // Byte of the W2 Byte Array.
        previousKey[8] = w2[0];
        // Set the Tenth Byte of the Previous
        // Round Key Byte Array As the Second
        // Byte of the W2 Byte Array.
        previousKey[9] = w2[1];
        // Set the Eleventh Byte of the Previous
        // Round Key Byte Array As the Third
        // Byte of the W2 Byte Array.
        previousKey[10] = w2[2];
        // Set the Twelveth Byte of the Previous
        // Round Key Byte Array As the Forth
        // Byte of the W2 Byte Array.
        previousKey[11] = w2[3];
        // Set the Thirteenth Byte of the Previous
        // Round Key Byte Array As the First
        // Byte of the W3 Byte Array.
        previousKey[12] = w3[0];   
        // Set the Fourteenth Byte of the Previous
        // Round Key Byte Array As the Second
        // Byte of the W3 Byte Array.
        previousKey[13] = w3[1];
        // Set the Fifthteenth Byte of the Previous
        // Round Key Byte Array As the Third
        // Byte of the W3 Byte Array.
        previousKey[14] = w3[2];     
        // Set the Sixteenth Byte of the Previous
        // Round Key Byte Array As the Forth
        // Byte of the W3 Byte Array.
        previousKey[15] = w3[3];
 
        // Return the Byte Array Composed
        // of All the Bytes Present Within
        // the Previous Round Key.
        return previousKey;
    }

    /**
     * This Method is Responsible for Calculating the Indexes of the
     * Substitution-Box Byte Entries which will be Swapped Out For the Current
     * HEXIDECIMAL Byte that Maps to it. (Ex. Byte 'A5' will Map to and be
     * Substituted for the Substitution Box Byte Value of '06'.) Once the
     * Substitution has be performed, the Byte Array Containing all of the
     * Substituted Byte Entries will be returned to the Calling Method.
     *
     * @param value         The The Four Byte Mixed Column Array Calculated 
     *                      in the Inverse Round Key Method.
     *
     * @return              The Substituted Four Byte Array That
     *                      will be used for Previous Round Key 
     *                      Generation.
     *
     */
    public static byte[] substituteBytes(byte[] value) {
        
        // Create new Array Value to Hold the
        // Final Array Result after the Subsitution
        // Process Has been Finished.
        byte[] subArray = new byte[4];
        
        // Create New Array to Hold the String
        // Converted HEXIDECIMAL Bytes in the
        // Parameter Byte Array.
        String[] sa = new String[4];
        
        // Format the Byte at Index 0 to Appear
        // as a HEXIDECIMAL String Value before Storing
        // it in the String Array.
        sa[0] = String.format("%02X ", value[0]);
        // Format the Byte at Index 1 to Appear
        // as a HEXIDECIMAL String Value before Storing
        // it in the String Array.
        sa[1] = String.format("%02X ", value[1]);
        // Format the Byte at Index 2 to Appear
        // as a HEXIDECIMAL String Value before Storing
        // it in the String Array.
        sa[2] = String.format("%02X ", value[2]);
        // Format the Byte at Index 3 to Appear
        // as a HEXIDECIMAL String Value before Storing
        // it in the String Array.
        sa[3] = String.format("%02X ", value[3]);
        
        // Create a new Array Which will be
        // Responsible for Storing the Individual
        // HEXIDECIMAL Char Values From The
        // Current Four Entry Byte Array.
        char[] chars = new char[8];
        
        // Get the First Char of the
        // the First Byte in the Array.
        chars[0] = sa[0].charAt(0);
        // Get the Second Char of the
        // the First Byte in the Array.
        chars[1] = sa[0].charAt(1);
        // Get the First Char of the
        // the Second Byte in the Array.
        chars[2] = sa[1].charAt(0);
        // Get the Second Char of the
        // the Second Byte in the Array.
        chars[3] = sa[1].charAt(1);
        // Get the First Char of the
        // the Third Byte in the Array.
        chars[4] = sa[2].charAt(0);
        // Get the Second Char of the
        // the Third Byte in the Array.
        chars[5] = sa[2].charAt(1);
        // Get the First Char of the
        // the Forth Byte in the Array.
        chars[6] = sa[3].charAt(0);
        // Get the Second Char of the
        // the Forth Byte in the Array.
        chars[7] = sa[3].charAt(1);
        
        // Create New Array to Hold the Integer
        // Values that each Individual Char Maps
        // To. These Values Will be used to
        // Calculate the Index Position in the
        // the Subsitution Box Where our Desired
        // Subsitute Byte is Located at.
        int[] charValues = new int[8];
        
        // Get the Integer Value Associated With
        // the First Character of the First Byte.
        charValues[0] = getCharIntValue(chars[0]);
        // Get the Integer Value Associated With
        // the Second Character of the First Byte.
        charValues[1] = getCharIntValue(chars[1]);
        // Get the Integer Value Associated With
        // the First Character of the Second Byte.
        charValues[2] = getCharIntValue(chars[2]);
        // Get the Integer Value Associated With
        // the Second Character of the Second Byte.
        charValues[3] = getCharIntValue(chars[3]);
        // Get the Integer Value Associated With
        // the First Character of the Third Byte.
        charValues[4] = getCharIntValue(chars[4]);
        // Get the Integer Value Associated With
        // the Second Character of the Third Byte.
        charValues[5] = getCharIntValue(chars[5]);
        // Get the Integer Value Associated With
        // the First Character of the Forth Byte.
        charValues[6] = getCharIntValue(chars[6]);
        // Get the Integer Value Associated With
        // the Second Character of the Forth Byte.
        charValues[7] = getCharIntValue(chars[7]);
        
        // Create New Array Used to Hold the
        // Calculated Indexes of the Byte Values
        // We will Use in the Subsitution Step
        // of the Reverse Key Generation Process.
        int[] subIndex = new int[4];
        
        // Calculate the Index of the Desired Byte Present
        // Within the Subsitution Box that Will be Subsituted
        // in Place of the First Byte in the Parameter Array.
        subIndex[0] = ((charValues[0] * 16) + charValues[1]);
        // Calculate the Index of the Desired Byte Present
        // Within the Subsitution Box that Will be Subsituted
        // in Place of the Second Byte in the Parameter Array.
        subIndex[1] = ((charValues[2] * 16) + charValues[3]);
        // Calculate the Index of the Desired Byte Present
        // Within the Subsitution Box that Will be Subsituted
        // in Place of the Third Byte in the Parameter Array.
        subIndex[2] = ((charValues[4] * 16) + charValues[5]);
        // Calculate the Index of the Desired Byte Present
        // Within the Subsitution Box that Will be Subsituted
        // in Place of the Forth Byte in the Parameter Array.
        subIndex[3] = ((charValues[6] * 16) + charValues[7]);
        
        // Finally, We Retrieve the HEXIDECIMAL Byte Values
        // Located At the Calculated Indexes Within the
        // Subsitution Box.
        
        // Retrieve the HEXIDECIMAL Subsitution Byte Value
        // For the First Byte in the Parameter Array.
        subArray[0] = (byte) SUBSITUTION_BOX[subIndex[0]];
        // Retrieve the HEXIDECIMAL Subsitution Byte Value
        // For the Second Byte in the Parameter Array.
        subArray[1] = (byte) SUBSITUTION_BOX[subIndex[1]];
        // Retrieve the HEXIDECIMAL Subsitution Byte Value
        // For the Third Byte in the Parameter Array.
        subArray[2] = (byte) SUBSITUTION_BOX[subIndex[2]];
        // Retrieve the HEXIDECIMAL Subsitution Byte Value
        // For the Forth Byte in the Parameter Array.
        subArray[3] = (byte) SUBSITUTION_BOX[subIndex[3]];
        
        // Return the Byte Array
        // Value Containing the
        // Subsituted Byte Values.
        return subArray;
    }
    
    /**
     *  This Method is Responsible for Retrieving the
     *  Round Constant Byte Value Associated With the
     *  Current Round and XORing the Value with the
     *  Bytes Present in the Parameter Byte Array.
     * 
     *  @param value            The Key Expansion Four
     *                          Byte Value Array Which
     *                          We will perform the Round
     *                          Constant Addition Step on.
     * 
     *  @return                 The New Byte Array Value
     *                          Result After the Round Constant
     *                          Addition Step has been performed.
     */
    public static byte[] addRoundConstant(byte[] value) {
        
        // Create New Byte Array Value Used to
        // Hold the Results of the Round Constant
        // Addition Process.
        byte[] rconArray = new byte[4];
        
        // In this Next Step, we will add the Round Constant
        // Byte Value Located at the Corresponding Round Number
        // Index in the ROUND_CONSTANT_BOX to the Parameter Byte
        // Array Value. This involves using a simple XOR Operation.
        // Seeing as the Round Constant Value is only a single
        // Byte, it means that we will XOR that Value with the
        // First Byte Present in the Parameter Array while the
        // other Bytes in the Parameter Array will be XOR-ed with
        // the Default Value of Zero. (Note: The Round Constant
        // Byte Value will be Different For Each Preceding Round.)
        //
        // XOR the Round Constant Value with the First Value
        // of the Parameter Byte Array.
        rconArray[0] = (byte) (value[0] ^ ROUND_CONSTANT_BOX[ROUND_NUMBER]);
        // XOR the Default Zero Byte Value with the Second Value
        // of the Parameter Byte Array.
        rconArray[1] = (byte) (value[1] ^ (byte) 0x00);
        // XOR the Default Zero Byte Value with the Third Value
        // of the Parameter Byte Array.
        rconArray[2] = (byte) (value[2] ^ (byte) 0x00);
        // XOR the Default Zero Byte Value with the Forth Value
        // of the Parameter Byte Array.
        rconArray[3] = (byte) (value[3] ^ (byte) 0x00);
        
        // Seeing as We Have now Finished
        // the Round Constant Addition Step,
        // Return the new Byte Array Value.
        return rconArray;
    }
    
    /**
     *  This Method is Used to Retrieve the Integer Value
     *  Associated with the parameter Hexidecimal Char Value.
     *  This Integer will be used in order to calculate the
     *  index location of the Current Hexidecimal Byte in one
     *  of the Global Byte[] Array Objects Above. Should the
     *  passed in character not be a Hexidecimal Character,
     *  the method will return a value of -1 which lets the
     *  calling method know that an Invalid Character is Present.
     * 
     *  @param value        The Hexidecimal Char Value Which we are trying
     *                      to receive the Decimal Equivalent Integer For.
     * 
     *  @return             The Decimal Integer Value which Corresponds
     *                      to the Parameter Hexidecimal Char Value or the
     *                      Value of -1 providing that the parameter Char
     *                      is an Invalid Hexidecimal Character.
     */
    public static int getCharIntValue(char value) {
        
        // Initialize a Integer
        // Value to Hold our Return
        // Value.
        int number = -1;

        // Try to Locate the Parameter
        // Char Value within the Switch
        // statement below. Should it be
        // found, set the return integer
        // to its corresponding Decimal
        // Equivalent Value.
        switch (value) {
            // If the Parameter 
            // Char is '0'
            case '0':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 0;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '1'
            case '1':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 1;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '2'
            case '2':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 2;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '3'
            case '3':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 3;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '4'
            case '4':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 4;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '5'
            case '5':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 5;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '6'
            case '6':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 6;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '7'
            case '7':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 7;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '8'
            case '8':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 8;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is '9'
            case '9':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 9;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'A' or 'a'
            case 'A':
            case 'a':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 10;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'B' or 'b'
            case 'B':
            case 'b':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 11;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'C' or 'c'
            case 'C':
            case 'c':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 12;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'D' or 'd'
            case 'D':
            case 'd':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 13;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'E' or 'e'
            case 'E':
            case 'e':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 14;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter 
            // Char is 'F' or 'f'
            case 'F':
            case 'f':
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = 15;
                // Break From Switch
                // Statement.
                break;
            // If the Parameter Char is
            // an Invalid Hexidecimal Character
            // Return the Error Value of -1.
            default:
                // Set Return Value As
                // Decimal Equivalent
                // Integer.
                number = -1;
                // Break From Switch
                // Statement.
                break;
        }
        
        // Return Either the Decimal
        // Equivalent of the Parameter
        // Hexidecimal Char Value or the
        // Error Value of -1.
        return number;
    }
    
    /**
     *  This Method is Used to Format the User's
     *  Inputted Round Key Value as a Valid String
     *  Value that the Program Can Manipulate without
     *  Causing Any Errors.
     * 
     *  @param value        The Round Key Value Inputted
     *                      By the User.
     * 
     *  @return             Formatted HEXIDECIMAL Round Key
     *                      Value.
     */
    public static String formatInputString(String value) {
        // Replace All Spaces in the User Input
        // String.
        value = value.replaceAll(" ", "");
        // Replace All New Line Characters in the
        // User Input String.
        value = value.replaceAll("\n", "");
        // Replace All Tab Characters in the
        // User Input String.
        value = value.replaceAll("\t", "");
        // Trim all Leading and Trailing White
        // Space from the Parameter String.
        value = value.trim();
        
        // Return Formatted String.
        return value;
    }
    
    /**
     *  This Method is Responsible for Converting
     *  The Parameter String into its HEXIDECIMAL
     *  Equivalent Value.
     * 
     *  @param value        The Parameter String.
     * 
     *  @return             The HEXIDECIMAL Converted
     *                      Parameter String.
     */
    public static byte[] byteArrayConversion(String value) {
        
        // Create a New Byte Array That Will
        // Be Responsible For Holding the
        // Bytes of the Converted String.
        byte[] conversion = new byte[16];
        
        // Create A Value to Hold
        // the First Char of the
        // Current Byte.
        char a;
        // Create A Value to Hold
        // the Second Char of the
        // Current Byte.
        char b;
        
        // Create Variable to Hold
        // the Integer Value of the
        // of the First Character in
        // the Current Byte.
        int aval;
        // Create Variable to Hold
        // the Integer Value of the
        // of the Second Character in
        // the Current Byte.
        int bval;
        
        // Create Variable to Hold the
        // Integer Index of the First
        // Character in the Current Byte.
        int startIndex = 0;
        // Create Variable to Hold the
        // Integer Index of the Second
        // Character in the Current Byte.
        int stopIndex = 1;
        
        // Continously Loop Until We Have Created
        // All 16 Bytes Used in the Round Key.
        for (int i = 0; i < 16; i++) {
            // Get the Char Value of the First
            // Char in the Current Byte.
            a = value.charAt(startIndex);
            // Get the Char Value of the Second
            // Char in the Current Byte.
            b = value.charAt(stopIndex);
            
            // Get the Integer Value of the First
            // Char in the Current Byte.
            aval = getCharIntValue(a);
            // Get the Integer Value of the Second
            // Char in the Current Byte.
            bval = getCharIntValue(b);
            
            // Add the First HEXIDECIMAL Byte Found
            // to the Current Index of the Round Key
            // Conversion Array.
            conversion[i] = HEXIDECIMAL_VALUES_LIST.get(aval)[bval];
            
            // Increment the Start Index Value
            // By two to begin the Next Byte and
            // Start on the Next First Char Value.
            startIndex = startIndex + 2;
            // Increment the Start Index Value
            // By two to begin the Next Byte and
            // Start on the Next Second Char Value.
            stopIndex = stopIndex + 2;
        }
        
        // Return the Converted Round Key
        // Byte Array Value.
        return conversion;
    }
    
    /**
     *  This method is responsible for Attempting to Decode the
     *  the Users Inputted Encrypted Message using the Advanced Encryption
     *  Standard (Electronic Code Block) Block Cipher Method.
     * 
     *  @param key                  The byte[] representation
     *                              of the User's Chosen Decryption
     *                              Key.
     * 
     *  @param message              The byte[] representation of
     *                              the User's Chosen Encrypted
     *                              message.
     * 
     *  @return                     The Resulting Decoded Cipher Text
     *                              String.
     */
    public static String decryptECBBlockCipher(byte[] key, byte[] message) {
        
        // Create New String Variable which will be responsible for holding
        // the final result of our Decryption Process.
        String result;
        
        try {
        
            // Create New Secret Key Object using the Original
            // Key Byte Array Value We Found.
            SecretKeySpec pKey = new SecretKeySpec(key, "AES");
            // Specify the AES Block Cipher Mode and the Type
            // of Padding Used.
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            
            // Set the Cipher Mode Object to invoke the Decryption
            // Process using both Secret Key Object.
            c.init(Cipher.DECRYPT_MODE, pKey);
            // Create new Array to hold the Decoded Message
            // and set its size to the Number of Bytes Present
            // within the Encrypted Message.
            byte[] decrypt = new byte[message.length];
            
            // Make sure the Cipher Object is Aware of an Uses
            // Encrypted Messages Size before performing the Operation.
            int ptLen = c.update(message, 0, message.length, decrypt, 0);
            // Perform Decryption Operation and Save
            // Returned Value in Decypt Byte Array.
            ptLen += c.doFinal(decrypt, ptLen);
            
            // Show the Decrypted Message as A String
            // and Return it to the Main Method.
            result = (new String(decrypt));
        }
        // This exception is thrown when a particular cryptographic 
        // algorithm is requested but is not available in the environment.
        catch (NoSuchAlgorithmException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        // This exception is thrown when a particular padding mechanism 
        // is requested but is not available in the environment.
        catch (NoSuchPaddingException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        // This is the exception for invalid Keys (invalid encoding, 
        // wrong length, uninitialized, etc).
        catch (InvalidKeyException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        // This exception is thrown when an output buffer provided 
        // by the user is too short to hold the operation result.
        catch (ShortBufferException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        // This exception is thrown when the length of data 
        // provided to a block cipher is incorrect, i.e., does 
        // not match the block size of the cipher.
        catch (IllegalBlockSizeException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        // This exception is thrown when a particular padding 
        // mechanism is expected for the input data but the data 
        // is not padded properly.
        catch (BadPaddingException ex) {
            // Show that the Decryption Process
            // Has Failed.
            result = ("Error");
        }
        
        // Return the Decryption Process
        // Result String.
        return result;
    }

    /**
     *  Main Method that Takes the Users Input
     *  and Performed the Necessary Operations.
     * 
     *  @param args     Parameter Arguments (NULL)
     */
    public static void main(String[] args) {
        // Initialize the Global HEX Value ArrayList
        InverseKeyGeneration inverseSecurityKey = new InverseKeyGeneration();
        
        // Create Scanner Object to Accept User Input.
        Scanner src = new Scanner(System.in);
        
        // Ask the User to Input the Value of the Last
        // Round Key in the Key Generation Process.
        System.out.println("Please Enter the Last Round Key: ");
        // Save Value in Global String Variable.
        ROUNDKEY_STRING = src.nextLine();
        
        // Run the User Input Value through the Formatter
        // Method.
        ROUNDKEY_STRING = formatInputString(ROUNDKEY_STRING);
        
        // Set the Number of Rounds to
        // Generate Previous Keys For.
        NUMBER_OF_ROUNDS = 10;
        
        // Set the Current Round
        // Number Integer
        ROUND_NUMBER = 10;
 
        // Convert the User Inputted 16 Character Round Key into
        // its Byte Array Equivalent Form.
        byte[] conversionkey = byteArrayConversion(ROUNDKEY_STRING);
        
        // Create an Array of String Builder Objects Which Will Be Used
        // Hold the Round Key String Values and the Original Key Value.
        StringBuilder[] sba = new StringBuilder[NUMBER_OF_ROUNDS];
        
        // Create a String Builder Object Which will be
        // Used to Print All the Current Round Key's Bytes into
        // A Single String with an Identifier Placed in Front.
        StringBuilder sb = new StringBuilder();
        
        // Add the Identifier to the String.
        sb.append("Round Key [" + 10 + "]:\t");
        
        // Loop Through All the Bytes Present Within the
        // the Conversion key array and format them to
        // Appear as a HEXIDECIMAL String Value.
        for (int a = 0; a < conversionkey.length; a++) {
            // Add the Next Converted Byte Value to the
            // String Builder Object.
            sb.append("0x").append(String.format("%02X ", conversionkey[a]));
        }
        
        // Print Out the First Round Key Value
        System.out.println("\n" + sb);
        
        // Create New Variable to Hold the Result
        // of our Previous Round Key Calculation.
        byte[] roundKey = new byte[16];
        
        // Add the User Inputted Round Key to the List.
        //ROUND_KEY_LIST.add(new RoundKey(ROUND_NUMBER, roundKey));
        
        // Continously Loop Until All Ten Rounds Have Been
        // Iterated Through and All Ten Previous Round Keys
        // Have Been Found.
        for (int i = 0; i < NUMBER_OF_ROUNDS; i++) {
            // If this is the First Found Key We
            // Are Trying to Find After the Recieving
            // the User's Inputted Round Key, Then
            // Find the Next Previous Round Key by
            // Passing the Conversion Key Byte Array
            // in as the Parameter.
            if (i == 0) {
                // Inverse the User Inputted Round Key to
                // Find the Next (Previous) Round Key in
                // the Sequence.
                roundKey = inverseRoundKey(conversionkey);
                // Add the Returned Previous Round Key Value
                // to the List of RoundKey Object.
                ROUND_KEY_LIST.add(new RoundKey(ROUND_NUMBER - 1, roundKey));
            }
            // If this is Not the First Round Key We Are
            // Trying to Find, then Pass the Previously
            // Generated Round Key in as the Parameter to
            // Each Subsequent Round Key Inversal Process.
            else {
                // Inverse the Returned Round Key Byte Array
                // Value to Find the Next (Previous) Round Key in
                // the Sequence.
                roundKey = inverseRoundKey(roundKey);
                // Add the Returned Previous Round Key Value
                // to the List of RoundKey Object.
                ROUND_KEY_LIST.add(new RoundKey(ROUND_NUMBER - 1, roundKey));
            }
            
            // Decrement the Current
            // Round Number Integer
            ROUND_NUMBER--;
        }
        
        // Loop through the Global ArrayList of our Generated 
        // Round Key Objects and Convert them into Strings For
        // User Viewing.
        for (int i = 0; i < ROUND_KEY_LIST.size(); i++) {
            
            // Create A Boolean Variable Which
            // is used to Let the Loop Know Whether
            // or Not the Identifier String has Already
            // Been Added to the Current Round Key String.
            boolean identifier = false;
            // Re-initialize the String Builder
            // Object to Allow it to Create Another
            // Round Key Formatted String.
            sb = new StringBuilder();
            
            // Loop Through All of the Bytes Present Within the Current Round
            // Key Byte Array Value, formatting Each Byte to Appear as a HEXIDECIMAL
            // String and Add them to the StringBuilder Object.
            for (int j = 0; j < ROUND_KEY_LIST.get(i).getKey().length; j++) {
                // If the Identifier String Phrase
                // Hasn't Been Added to the Current
                // Round Key String, Add it Before
                // Adding the First Byte Value.
                if (identifier == false) {
                    // Check to See if the Current Key is the Last
                    // Round Key (Key 0) Which Also Doubles as the
                    // Original Key Used In the Encryption Process.
                    if (ROUND_KEY_LIST.get(i).getRoundNumber() == 0) {
                        // Add Identifier String to String Builder String.
                        sb.append("\nOriginal Key:\t");
                        // Let the Loop Know that the Round
                        // Key Identifier has Been Added.
                        identifier = true;
                    }
                    else {
                        // Add Identifier String to String Builder String.
                        sb.append("Round Key [").append(ROUND_KEY_LIST.get(i).getRoundNumber()).append("]:\t");
                        // Let the Loop Know that the Round
                        // Key Identifier has Been Added.
                        identifier = true;
                    }
                }
                // Format the Current Byte Object to its HEXIDECIMAL String
                // Version and Add it to the List.
                sb.append("0x").append(String.format("%02X ", ROUND_KEY_LIST.get(i).getKey()[j]));
            }
            
            // Set the Current String Builder
            // Object as the Next Index of the
            // String Builder Object Array.
            sba[i] = sb;
        }
        
        // Loop through the Array of String
        // Builder Objects and Print Out Each One.
        for (int i = 0; i < sba.length; i++) {
            // Print Out the String Value.
            System.out.println(sba[i]);
        }
        
        // Try to Decrypt the Encrypted Cipher Text
        // Message Using the Original Ecryption Key
        // We Found Earlier.
        String decryptedMessage = decryptECBBlockCipher(ROUND_KEY_LIST.get(ROUND_KEY_LIST.size() - 1).getKey(), MESSAGE_BYTE_ARRAY);
        
        // Print Identifier String.
        System.out.println("\nDecrypted Message: ");
        // Print Decrypted Message.
        System.out.println(decryptedMessage);
    }
}
