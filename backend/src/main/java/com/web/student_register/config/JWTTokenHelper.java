package com.web.student_register.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
@Service
@Configuration
public class JWTTokenHelper {
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private RSAProperties rSAProperties;

    @Value("${jwt.auth.app}")
    private String appName;
    @Value("${jwt.auth.expires_in}")
    private int expireIn;

    private SignatureAlgorithm SIGNATURE_ALGORITHM;

    public JWTTokenHelper(RSAProperties rSAProperties){
        this.rSAProperties = rSAProperties;
        loadKeys();
        this.SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;
    }



    private void loadKeys() {

        try {
            //Create Instance of RSA
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //Convert the privateKey into array of Bytes
            PKCS8EncodedKeySpec privateKeySpeckeySpec =
                    new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(rSAProperties.getPrivateKey()));

            //Assign and Cast private key into RSAPrivateKey
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpeckeySpec);

            //Convert the publicKey into array of Bytes
            X509EncodedKeySpec publicKeySpec =
                    new X509EncodedKeySpec(Base64.getMimeDecoder().decode(rSAProperties.getPublicKey()));

            //Assign and Cast public key into RSAPublicKey
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateToken(String userName) throws InvalidKeyException, NoSuchAlgorithmException {
        String token = Jwts.builder()
                .setIssuer(appName)
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(generateExpirationDate())
                .signWith(SIGNATURE_ALGORITHM, privateKey)
                .compact();

        return token;
    }

    public Date generateExpirationDate(){
        return new Date(new Date().getTime() + expireIn*1000) ;
    }

    public String getToken(HttpServletRequest request){
        String authHeader = getHeaderFromHeader(request);
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;
    }

    private String getHeaderFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return header;
    }

    public Claims getAllClaimFromToken(String token){
        Claims claims;
        try{
            claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
        }catch(Exception e){
            claims = null;
        }

        return claims;
    }

    public String getUserNameFromToken(String token){
        String userName;
        try{
            final Claims claims = getAllClaimFromToken(token);
            userName = claims.getSubject();

        }catch(Exception e){

            userName = null;
        }
        return userName;
    }

    public boolean validateToken(String token, UserDetails userDetails){
        final String userName = getUserNameFromToken(token);
        if(userName != null && userName.equals(userDetails.getUsername()) && !isTokenExpired(token)){
            return true;
        }
        return false;
    }

    private boolean isTokenExpired(String token) {
        Date expiryDate = getExpireDateFromToken(token);
        return expiryDate.before(new Date());
    }

    private Date getExpireDateFromToken(String token) {
        Date expiryDate;
        try{
            final Claims claims = getAllClaimFromToken(token);
            expiryDate = claims.getExpiration();
        }catch(Exception e){
            expiryDate = null;
        }
        return expiryDate;
    }
}
