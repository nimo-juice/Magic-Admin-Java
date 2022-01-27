package magic_auth.dto;

import lombok.Data;

@Data
public class UserMetadata {
    String issuer;
    String publicAddress;
    String email;
    String oauthProvider;
    String phoneNumber;
}
