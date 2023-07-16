package dev.arov.googlecloudfunctions;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.quarkus.logging.Log;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Path("/jwt")
public class JwtIssuer {
    @ConfigProperty(name = "jwt.private-key", defaultValue = " ")
    String privateKey;

    @ConfigProperty(name = "jwt.public-key", defaultValue = " ")
    String publicKey;

    @ConfigProperty(name = "jwt.kid", defaultValue = "default")
    String kid;

    @POST
    public JwtResponse issue(ObjectNode payload) {
        var resp = new JwtResponse();

        var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build();
        JWSObject jwsObject = new JWSObject(header, new Payload(payload.toString()));
        try {
            var pKey = privateKey.isBlank() ? loadPrivateKeyFromDefaultFile() : loadPrivateKeyFromString(privateKey);
            jwsObject.sign(new RSASSASigner(pKey));
        } catch (Exception e) {
            Log.error("Unable to sign JWT", e);
            resp.error = "Unable to sign JWT at this time.";
            return resp;
        }

        resp.token = jwsObject.serialize();
        return resp;
    }

    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Path("/verify")
    public Response verify(String token) {
        try {
            var jwsObject = JWSObject.parse(token);
            var pKey = publicKey.isBlank() ? loadPublicKeyFromDefaultFile() : loadPublicKeyFromString(publicKey);
            if (!jwsObject.verify(new RSASSAVerifier((RSAPublicKey) pKey)))
                return Response.status(Response.Status.UNAUTHORIZED).entity("{ \"status\": \"JWT invalid\" }").build();
            return Response.status(Response.Status.OK).entity("{ \"status\": \"JWT valid\" }").build();
        } catch (Exception e) {
            Log.error("Unable to verify JWT", e);
            return Response.status(500).entity("{ \"error\": \"something went wront while verifying JWT\" }").build();
        }
    }

    @Path("/jwks")
    @GET
    public String getJwks() {
        try {
            JWK jwk = new RSAKey.Builder((RSAPublicKey) (publicKey.isBlank() ? loadPublicKeyFromDefaultFile() : loadPublicKeyFromString(publicKey)))
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(kid)
                    .build();
            return "{\"keys\":[" + jwk.toJSONString() + "]}";
        } catch (Exception e) {
            Log.error("Unable to load public key", e);
            return "{\"error\":\"Unable to load public key at this time.\"}";
        }
    }

    private PrivateKey loadPrivateKeyFromString(String pKey) {
        try {
            String privateKeyContent = pKey.replaceAll("\\n", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            return kf.generatePrivate(keySpecPKCS8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static class JwtResponse {
        public String token;
        public String error;
    }

    private PrivateKey loadPrivateKeyFromDefaultFile() {
        Log.info("Loading private key from default file");
        try (var stream = JwtIssuer.class.getClassLoader().getResourceAsStream("private_key_pkcs8.pem")) {
            if (stream == null)
                throw new RuntimeException("Unable to load private key from default file");
            var privateKeyContent = new String(stream.readAllBytes());
            return loadPrivateKeyFromString(privateKeyContent);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private PublicKey loadPublicKeyFromString(String publicKeyContent) {
        try {

            publicKeyContent = publicKeyContent.replaceAll("\\n", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            return kf.generatePublic(keySpecX509);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PublicKey loadPublicKeyFromDefaultFile() {
        Log.info("Loading public key from default file");
        try (var stream = JwtIssuer.class.getClassLoader().getResourceAsStream("public_key.pem")) {
            if (stream == null)
                throw new RuntimeException("Unable to load public key from default file");
            var publicKeyContent = new String(stream.readAllBytes());
            return loadPublicKeyFromString(publicKeyContent);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
