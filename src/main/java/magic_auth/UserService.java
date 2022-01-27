package magic_auth;

import com.google.gson.Gson;
import lombok.AllArgsConstructor;
import magic_auth.dto.UserMetadata;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@AllArgsConstructor
public class UserService {
    private final static String BASE_URL = "https://api.magic.link";
    private final static String V1_USER_INFO = "/v1/admin/auth/user/get";
    private final static String V2_USER_LOGOUT = "/v2/admin/auth/user/logout";
    private final static String SECRET_KEY_HEADER = "X-Magic-Secret-Key";
    private final static HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    private final String apiSecretKey;

    public UserMetadata getMetadataByIssuer(String issuer) throws java.io.IOException, java.lang.InterruptedException {
        var request = getRequest(V1_USER_INFO + "?issuer=" + issuer);
        var response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        return new Gson().fromJson(response.body(), UserMetadata.class);
    }

    public void logoutByIssuer(String issuer) throws java.io.IOException, java.lang.InterruptedException {
        var request = getRequest(V2_USER_LOGOUT + "?issuer=" + issuer);
        HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest getRequest (String path) {
        return HttpRequest
                .newBuilder(URI.create(BASE_URL + path))
                .header("accept", "application/json")
                .header(SECRET_KEY_HEADER, this.apiSecretKey)
                .build();
    }
}
