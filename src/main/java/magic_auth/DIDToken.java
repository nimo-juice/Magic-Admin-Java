package magic_auth;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DIDToken {
    public String iat;
    public String ext;
    public String iss;
    public String sub;
    public String aud;
    public String nbf;
    public String tid;
    public String add;
}
