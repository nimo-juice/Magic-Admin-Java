package magic_auth;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.Arrays;

public class Cryptography {
    public static String ecRecover(String claim, String signature) {
        var hexMessage = Sign.getEthereumMessageHash(claim.getBytes());

        ECDSASignature esig = getECDSASignature(signature);
        System.out.println("esig: " + esig);
        BigInteger res = Sign.recoverFromSignature(0, esig, hexMessage);

        return Keys.getAddress(res);
    }

    private static ECDSASignature getECDSASignature(String signature) {
        byte[] signatureBytes = signature.getBytes();

        if (signatureBytes.length < 65) {
            throw new MalformedTokenException();
        }

        var r = Arrays.copyOfRange(signatureBytes, 0, 32);
        var s = Arrays.copyOfRange(signatureBytes, 32, 64);

        return new ECDSASignature(Numeric.toBigInt(r), Numeric.toBigInt(s)).toCanonicalised();
    }
}
