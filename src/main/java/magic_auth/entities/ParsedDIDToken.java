package magic_auth.entities;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class ParsedDIDToken {
    public DIDToken parsedDIDToken;
    public String signature;
    public String claim;
}
