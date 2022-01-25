import magic_auth.Magic;
import org.json.JSONArray;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

public class TestMagicAuth {

    private static final String signature = "0x0016ff542ab7143cf598ebd3f4960243aee23a628ffd75aa87848cfcc70aa93f7ed294da3cb98c2555b387d358e76318c2e4babd73cd5a7a26f6f7bb3a2949fa1c";
    private static final String claim = "{\"iat\":1642092397,\"ext\":1642093297,\"iss\":\"did:ethr:0x750332BDf3D7BCC0644efC18D1fF6487f78C9402\",\"sub\":\"Q0caeWHvKDsQvJrGbDElDmtejgROsVF4uABQhWthR6Q=\",\"aud\":\"9OhuSJuPb4Zxh3HIFsqbhSN8Quiz8FCu-Cl55BdmaWY=\",\"nbf\":1642092397,\"tid\":\"9e5acd85-d604-4fd9-bb0b-d1fab5801885\",\"add\":\"0x59ea19cbe3d495c96de3372d53a9043874e361ecf091c05726c8297c74ef85ea112c0a1527bf6269010a6a02d4f27c2f0f17da96e2d6f74f2f00d2a1f1aed1191b\"}";

    @Test
    public void testJsonParsing() {
        var jsonToken = new JSONArray().put(signature).put(claim).toString();
        var base64JsonToken = Base64.getEncoder().withoutPadding().encodeToString(jsonToken.getBytes());
        var parsedToken = Magic.parseDIDToken(base64JsonToken);

        assertEquals(parsedToken.getClaim(), claim);
        assertEquals(parsedToken.getSignature(), signature);

        var parsedDidToken = parsedToken.getParsedDIDToken();
        assertEquals(parsedDidToken.getExpiredAt(), 1642093297L);
        assertEquals(parsedDidToken.getIssuedAt(), 1642092397L);
        assertEquals(parsedDidToken.getIssuer(), "did:ethr:0x750332BDf3D7BCC0644efC18D1fF6487f78C9402");
        assertEquals(parsedDidToken.getSubject(), "Q0caeWHvKDsQvJrGbDElDmtejgROsVF4uABQhWthR6Q=");
        assertEquals(parsedDidToken.getAudience(), "9OhuSJuPb4Zxh3HIFsqbhSN8Quiz8FCu-Cl55BdmaWY=");
        assertEquals(parsedDidToken.getNotBefore(), 1642092397L);
        assertEquals(parsedDidToken.getDidTokenId(), "9e5acd85-d604-4fd9-bb0b-d1fab5801885");
        assertEquals(parsedDidToken.getAdditional(), "0x59ea19cbe3d495c96de3372d53a9043874e361ecf091c05726c8297c74ef85ea112c0a1527bf6269010a6a02d4f27c2f0f17da96e2d6f74f2f00d2a1f1aed1191b");
    }

    @Test
    public void testVerify() {
        var jsonToken = new JSONArray().put(signature).put(claim).toString();
        var base64JsonToken = Base64.getEncoder().withoutPadding().encodeToString(jsonToken.getBytes());
        var parsedToken = Magic.parseDIDToken(base64JsonToken);

        String instantExpected = "2022-01-13T16:56:37Z";
        Clock clock = Clock.fixed(Instant.parse(instantExpected), ZoneId.of("UTC"));
        Instant instant = Instant.now(clock);

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);
            assertDoesNotThrow(() -> Magic.validateDIDToken(parsedToken));
        }
    }
}
