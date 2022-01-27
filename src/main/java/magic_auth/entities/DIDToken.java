package magic_auth.entities;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotNull;

@Data
@AllArgsConstructor
public class DIDToken {
    @NotNull
    @SerializedName("iat")
    long issuedAt;

    @NotNull
    @SerializedName("ext")
    long expiredAt;

    @NotNull
    @SerializedName("iss")
    String issuer;

    @NotNull
    @SerializedName("sub")
    String subject;

    @NotNull
    @SerializedName("aud")
    String audience;

    @NotNull
    @SerializedName("nbf")
    long notBefore;

    @NotNull
    @SerializedName("tid")
    String didTokenId;

    @SerializedName("add")
    String additional;
}
