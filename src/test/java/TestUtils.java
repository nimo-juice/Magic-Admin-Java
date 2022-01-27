import lombok.Data;
import org.json.JSONArray;

import java.util.Base64;

@Data
public class TestUtils {
    public static final String signature = "0x0016ff542ab7143cf598ebd3f4960243aee23a628ffd75aa87848cfcc70aa93f7ed294da3cb98c2555b387d358e76318c2e4babd73cd5a7a26f6f7bb3a2949fa1c";
    public static final String claim = "{\"iat\":1642092397,\"ext\":1642093297,\"iss\":\"did:ethr:0x750332BDf3D7BCC0644efC18D1fF6487f78C9402\",\"sub\":\"Q0caeWHvKDsQvJrGbDElDmtejgROsVF4uABQhWthR6Q=\",\"aud\":\"9OhuSJuPb4Zxh3HIFsqbhSN8Quiz8FCu-Cl55BdmaWY=\",\"nbf\":1642092397,\"tid\":\"9e5acd85-d604-4fd9-bb0b-d1fab5801885\",\"add\":\"0x59ea19cbe3d495c96de3372d53a9043874e361ecf091c05726c8297c74ef85ea112c0a1527bf6269010a6a02d4f27c2f0f17da96e2d6f74f2f00d2a1f1aed1191b\"}";

    public static String getValidBase64Token() {
        var jsonToken = new JSONArray().put(signature).put(claim).toString();
        return Base64.getEncoder().withoutPadding().encodeToString(jsonToken.getBytes());
    }

    public static String getInvalidBase64Token() {
        var jsonToken = new JSONArray().put("signature").put("claim").toString();
        return Base64.getEncoder().withoutPadding().encodeToString(jsonToken.getBytes());
    }
}
