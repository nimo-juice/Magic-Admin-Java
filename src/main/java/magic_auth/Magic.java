package magic_auth;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;

import java.time.Instant;
import java.util.Base64;

@Slf4j
@RequiredArgsConstructor
public class Magic {

    private final static Integer LEEWAY_TIME_MILLI = 60 * 1_000; // 60 milliseconds

    public static ParsedDIDToken parseDIDToken(String didToken) {
        byte[] decodedBytes = Base64.getDecoder().decode(didToken);
        String decodedString = new String(decodedBytes);
        JSONArray jsonArray = new JSONArray(decodedString);
        String signature = (String) jsonArray.get(0);
        String claim = (String) jsonArray.get(1);
        try {
            DIDToken parsedDidToken = new Gson().fromJson(claim, DIDToken.class);
            return ParsedDIDToken.builder().parsedDIDToken(parsedDidToken).signature(signature).claim(claim).build();
        } catch (Exception ex) {
            throw new MalformedTokenException();
        }
    }

    public static void validateDIDToken(ParsedDIDToken parsedDIDToken) {
        String claimedIssuer;

        try {
            claimedIssuer = parsedDIDToken.parsedDIDToken.iss.split(":")[2];
        } catch (Exception e) {
            throw new MalformedTokenException();
        }

//        validateClaim(claimedIssuer, parsedDIDToken);
        validateEXT(parsedDIDToken.getParsedDIDToken().getExt());
        validateNBF(parsedDIDToken.getParsedDIDToken().getNbf());
    }

    private static void validateClaim(String claimedIssuer, ParsedDIDToken parsedDIDToken) throws IncorrectSignerException {
        var claim = parsedDIDToken.getClaim();
        var signature = parsedDIDToken.getSignature();

        var recoveredClaimAddress = Cryptography.ecRecover(claim, signature);

        if (!recoveredClaimAddress.equals(claimedIssuer)) {
            throw new IncorrectSignerException();
        }
    }

    private static void validateEXT(String ext) throws IncorrectSignerException {
        Instant instant = Instant.now();
        var utcTimeNow = instant.getEpochSecond();

        if (Integer.parseInt(ext) < utcTimeNow) {
            throw new IncorrectSignerException();
        }
    }

    private static void validateNBF(String nbf) throws IncorrectSignerException {
        Instant instant = Instant.now();
        var utcTimeNow = instant.getEpochSecond();

        if (Integer.parseInt(nbf) > utcTimeNow - LEEWAY_TIME_MILLI) {
            throw new IncorrectSignerException();
        }
    }


}
