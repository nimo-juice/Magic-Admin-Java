package magic_auth;

import lombok.Data;
import magic_auth.entities.ParsedDIDToken;
import magic_auth.dto.UserMetadata;

@Data
public class Magic {
    private final UserService userService;

    public Magic (String apiSecretKey) {
        this.userService = new UserService(apiSecretKey);
    }

    public static void validateToken(String didToken) {
        ParsedDIDToken parsedDIDToken = TokenService.parseDIDToken(didToken);
        TokenService.validateDIDToken(parsedDIDToken);
    }

    // Get metadata API calls
    public UserMetadata getMetadataByIssuer(String issuer) throws java.io.IOException, java.lang.InterruptedException {
        return this.userService.getMetadataByIssuer(issuer);
    }

    public UserMetadata getMetadataByToken(String didToken) throws java.io.IOException, java.lang.InterruptedException {
        var parsedDIDToken = TokenService.parseDIDToken(didToken);
        var issuer = parsedDIDToken.getParsedDIDToken().getIssuer();
        return this.getMetadataByIssuer(issuer);
    }

    public UserMetadata getMetadataByPublicAddress(String publicAddress) throws java.io.IOException, java.lang.InterruptedException {
        var issuer = TokenService.getIssuerFromPublicAddress(publicAddress);
        return this.getMetadataByIssuer(issuer);
    }

    // Logout API calls
    public void logoutByIssuer(String issuer) throws java.io.IOException, java.lang.InterruptedException {
        this.userService.logoutByIssuer(issuer);
    }

    public void logoutByToken(String didToken) throws java.io.IOException, java.lang.InterruptedException {
        var parsedDIDToken = TokenService.parseDIDToken(didToken);
        var issuer = parsedDIDToken.getParsedDIDToken().getIssuer();
        this.logoutByIssuer(issuer);
    }

    public void logoutByPublicAddress(String publicAddress) throws java.io.IOException, java.lang.InterruptedException {
        var issuer = TokenService.getIssuerFromPublicAddress(publicAddress);
        this.logoutByIssuer(issuer);
    }
}

