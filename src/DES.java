
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class DES {

    /**
     * Encrypts the given message using DES algorithm
     * with the given private key.
     *
     * @param message a 64-bit message.
     * @param key     a 64-bit private key.
     *
     * @return the 64-bit encrypted message.
     */
    public static long encrypt(long message, long key) {
        List<Long> keys = generateKeys(key);
        return des(message, keys);
    }

    /**
     * Decrypts the given ciphertext using DES algorithm
     * with the given private key.
     *
     * @param ciphertext a 64-bit ciphertext.
     * @param key        a 64-bit private key.
     *
     * @return the 64-bit decrypted message.
     */
    public static long decrypt(long ciphertext, long key) {
        List<Long> keys = generateKeys(key);
        Collections.reverse(keys);
        return des(ciphertext, keys);
    }

    /**
     * Applies DES algorithm on the given message using the given
     * list of private keys for each DES round.
     *
     * @param message a 64-bit message.
     * @param keys    a list of 16 keys for each DES round.
     *
     * @return a 64-bit encrypted message.
     */
    private static long des(long message, List<Long> keys) {
        // Permute the message using initial permutation
        // The output is 64 bits
        message = permute(message, 64, Constants.IP);

        // Split the key into left and right part each of 28 bits
        int len = (Constants.IP.length >> 1);
        long L = (message >>> len);                 // Left part
        long R = (message & ((1L << len) - 1));     // Right part

        // Execute the 16 rounds of DES algorithm
        for (long key : keys) {
            long L_new = R;
            long R_new = L ^ feistelFunc(R, key);

            L = L_new;
            R = R_new;
        }

        // Finally, permute the result once again using inverse initial permutation.
        return permute((R << len) | L, 64, Constants.IP_INV);
    }

    /**
     * Generates a 16 different keys for each DES round based
     * on the given private key.
     *
     * @param key a 64-bit private key.
     *
     * @return a list of 16 48-bit keys for each DES round.
     */
    public static List<Long> generateKeys(long key) {
        // The list of keys to be populated and returned
        List<Long> ret = new ArrayList<>();

        // Permute the key using permuted choice 1
        // The output is 56 bits
        key = permute(key, 64, Constants.PC_1);

        // Split the key into left and right part each of 28 bits
        int len = (Constants.PC_1.length >> 1);
        long C = (key >>> len);                 // Left part
        long D = (key & ((1L << len) - 1));     // Right part

        // Generate a key for each round of DES algorithm
        for (int i = 0; i < Constants.DES_ROUNDS; ++i) {
            // Rotate left each part separately
            for (int j = 0; j < Constants.ROTATION_COUNT[i]; ++j) {
                C = rotateLeft(C, len);
                D = rotateLeft(D, len);
            }

            // Permute the concatenation of 'C' & 'D' using permute choice 2
            // The output is 48 bits
            long K = permute((C << len) | D, len << 1, Constants.PC_2);

            // Append key to the list
            ret.add(K);
        }

        // Return the list of keys
        return ret;
    }

    /**
     * Applies Feistel function on the given right half of the data
     * of a specific DES round using the given key of that round
     *
     * @param R the 32-bit right half of the data of a specific DES round.
     * @param K the 48-bit key of that DES round.
     *
     * @return a 32-bit after applying f(R, K).
     */
    private static long feistelFunc(long R, long K) {
        long ret = 0;

        // Expand the message to 48 bits and xor it with the K
        R = permute(R, 32, Constants.EP) ^ K;

        // Now we have 48 bits, or eight groups of 6 bits
        // We will shrink each group from 6 bits to 4 bits
        // So that the results become 32 bits again
        int size = Constants.S_BOXES.length;

        for (int i = 0; i < size; ++i) {
            int[][] sBox = Constants.S_BOXES[size - i - 1];
            int block = (int) (R & ((1L << 6) - 1));
            int r = ((block >>> 5) << 1) | (block & 1);
            int c = ((block >>> 1) & 0xF);

            R >>>= 6;
            ret |= (sBox[r][c] << (i * 4));
        }

        // Finally, permute the result once again
        return permute(ret, 32, Constants.PF);
    }

    /**
     * Permutes the given data using the given permutation array.
     *
     * @param data the data to permute.
     * @param len  the initial length of the data.
     * @param perm the needed permutation.
     *
     * @return the data after permutation.
     */
    private static long permute(long data, int len, int[] perm) {
        long ret = 0;

        for (int i = 0; i < perm.length; ++i) {
            if ((data & (1L << (len - perm[i]))) != 0) {
                ret |= (1L << (perm.length - i - 1));
            }
        }

        return ret;
    }

    /**
     * Rotates the given data one bit to the left.
     *
     * @param data the data to rotate left.
     * @param len  the length of the data.
     *
     * @return the data after rotation.
     */
    private static long rotateLeft(long data, int len) {
        long ret = (data << 1) & ((1L << len) - 1);

        if ((data & (1L << (len - 1))) != 0) {
            ret |= 1;
        }

        return ret;
    }
}
