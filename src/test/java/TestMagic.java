import magic_auth.Magic;
import magic_auth.exceptions.MalformedTokenException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

public class TestMagic {
    @Test
    public void testValidateToken() {
        var base64JsonToken = TestUtils.getValidBase64Token();
        String instantExpected = "2022-01-13T16:56:37Z";
        Clock clock = Clock.fixed(Instant.parse(instantExpected), ZoneId.of("UTC"));
        Instant instant = Instant.now(clock);
        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);
            assertDoesNotThrow(() -> Magic.validateToken(base64JsonToken));
        }
    }

    @Test
    public void testInvalidToken() {
        assertThrows(IllegalArgumentException.class, () -> Magic.validateToken("random invalid token string"));
        assertThrows(MalformedTokenException.class, () -> Magic.validateToken(TestUtils.getInvalidBase64Token()));
    }

    @Test
    public void testMetadata() {
    }
}
