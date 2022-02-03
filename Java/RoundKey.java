/**
 *  This Class is Responsible For Creating
 *  A Custom Round Key Object Which Holds An
 *  Integer Value Containing the Round Number
 *  Associated with the Current Key Instance
 *  in Addition to A Byte Array Value which
 *  Holds the Individual Bytes that the
 *  Current Round Key is Composed Of.
 * 
 *  @date October 4, 2020
 *  @author Tyler Fontana
 *  @version 1.0.0
 */
public class RoundKey {
    
    // The Round Number
    public int number;
    // The Array of Bytes That
    // the Round Key is
    // Composed of.
    public byte[] key;
    
    /**
     *  Constructor Method That is Used to
     *  Create a New Instance of the Round
     *  Key Object.
     * 
     *  @param round        The Current Round
     *                      Number that the Key
     *                      is Associated With.
     * 
     *  @param value        The Byte Array Holding
     *                      all the Individual Bytes
     *                      that the Round Key is
     *                      Composed of.
     */
    public RoundKey(int round, byte[] value) {
        // Set Round Number
        this.number = round;
        // Set Key Byte Array
        this.key = value;
    }
    
    /**
     *  A Getter Method that is Responsible for
     *  Retrieving the Round Number Assoicated
     *  With the Current Instance of This Round Key.
     * 
     *  @return             The Integer Round Number
     *                      Associated with the Round Key.
     */
    public int getRoundNumber() {
        // Return Round Number
        return this.number;
    }
    
    /**
     *  A Getter Method that is Responsible for
     *  Retrieving the Byte Array Containing all
     *  all the Bytes that the Current Round Key
     *  is Composed of.
     * 
     *  @return             The Byte Array Value
     *                      Containing the Round Key
     */
    public byte[] getKey() {
        // Return Key Byte Array
        return this.key;
    }
    
    /**
     *  A Setter Method that is used to Set the
     *  Round Number Associated With the Current
     *  Round Key Instance.
     * 
     *  @param value        The Round Number
     */
    public void setRoundNumber(int value) {
        // Set Round Number
        this.number = value;
    }
    
    /**
     *  A Setter Method that is used to Set the
     *  Byte Array Value of the Current Round Key
     *  Instance.
     * 
     *  @param value        The Byte Array Containing
     *                      All of the Bytes that the
     *                      Current Round Key is Composed
     *                      of.
     */
    public void setKey(byte[] value) {
        // Set Byte Array Value.
        this.key = value;
    }
}
