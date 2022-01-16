package io.jsonwebtoken.jjwtfun.controller;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.compression.CompressionCodecs;
import io.jsonwebtoken.jjwtfun.model.JwtResponse;
import io.jsonwebtoken.jjwtfun.service.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
public class DynamicJWTController extends BaseController {

    //TODO Learn HS256 standard
    //HMAC ---> In cryptography, an HMAC is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key.
    // ... s an algorithm that combines a certain payload with a secret using a cryptographic hash function like SHA-256 .

    //RS256 and HS256 are algorithms used for signing a JWT. RS256 is an asymmetric algorithm, meaning it uses a public and private key pair. HS256 is a symmetric algorithm, meaning it uses a shared secret. Auth0 uses RS256 as the default signing algorithm in JWTs.

    @Autowired
    SecretService secretService;

    @RequestMapping(value = "/dynamic-builder-general", method = POST)
    public JwtResponse dynamicBuilderGeneric(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        String jws = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes())
                .compact();
        return new JwtResponse(jws);
    }

    //If you have a lot of claims on a JWT, it can get big – so big, that it might not fit in a GET url in some browsers.
    //Let's a make a big JWT:
    @RequestMapping(value = "/dynamic-builder-compress", method = POST)
    public JwtResponse dynamicBuildercompress(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        String jws = Jwts.builder()
                .setClaims(claims)
                .compressWith(CompressionCodecs.DEFLATE)
                .signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes())
                .compact();
        return new JwtResponse(jws);

        //Uncompressed jws - Much longer than compressed version ... more claims result in longer jws
        //eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTdG9ybXBhdGgiLCJoYXNNb3RvcmN5Y2xlIjp0cnVlLCJzdWIiOiJtc2lsdmVybWFuIiwidGhlIjoicXVpY2siLCJicm93biI6ImZveCIsImp1bXBlZCI6Im92ZXIiLCJsYXp5IjoiZG9nIiwic29tZXdoZXJlIjoib3ZlciIsInJhaW5ib3ciOiJ3YXkiLCJ1cCI6ImhpZ2giLCJhbmQiOiJ0aGUiLCJkcmVhbXMiOiJ5b3UiLCJkcmVhbWVkIjoib2YifQ.AHNJxSTiDw_bWNXcuh-LtPLvSjJqwDvOOUcmkk7CyZA

        //Compressed jws
        //eyJhbGciOiJIUzI1NiIsInppcCI6IkRFRiJ9.eNpEzk0SwiAMBeC7ZN0T9A6uPEFK04ICqfyItdO7-xjHcRU-8ibJQcazC5nGg1xGoWvRFDYulgaynC8Km914obGkKgPlOiEWsvNPSYEjcsWiS4_qzB2akrYIL_qCbjVsMoOKOOz5vUOzrkDWIM1Kkn8_sYuTNnw03uG64Wnd2u_h2Af1bQPNSbjfTbvWH797FjrPDwAAAP__.ePCBSOfChtvhyzsSXSK18LiayO-zQRM1mnY_MnG9IyQ

    }

    @RequestMapping(value = "/dynamic-builder-specific", method = POST)
    public JwtResponse dynamicBuilderSpecific(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        JwtBuilder builder = Jwts.builder();

        claims.forEach((key, value) -> {
            switch (key) {
                case "iss":
                    ensureType(key, value, String.class);
                    builder.setIssuer((String) value);
                    break;
                case "sub":
                    ensureType(key, value, String.class);
                    builder.setSubject((String) value);
                    break;
                    //Example of custom claim to authenticate in the request's token
                case "hasMotorcycle":
                    ensureType(key, value, Boolean.class);
                    throwExceptionIfMotorcycleIsFalse(value);
                    builder.setSubject(String.valueOf( value));
                    break;
                case "anyCustomClaimWeWantToAddInRequest":
                    ensureType(key, value, String.class);
                    builder.setSubject((String) value);
                    break;
                case "aud":
                    ensureType(key, value, String.class);
                    builder.setAudience((String) value);
                    break;
                case "exp":
                    ensureType(key, value, Long.class);
                    builder.setExpiration(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "nbf":
                    ensureType(key, value, Long.class);
                    builder.setNotBefore(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "iat":
                    ensureType(key, value, Long.class);
                    builder.setIssuedAt(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "jti":
                    ensureType(key, value, String.class);
                    builder.setId((String) value);
                    break;
                default:
                    builder.claim(key, value);
            }
        });



        builder.signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes());

        return new JwtResponse(builder.compact());
    }

    //Class<?> ---> Use instead of Raw Class because ... https://stackoverflow.com/questions/9921676/what-does-class-mean-in-java
    //Class is a parameterizable class, hence you can use the syntax Class<T> where T is a type. By writing Class<?>, you're declaring a Class object which can be of any type (? is a wildcard). The Class type is a type that contains meta-information about a class.
    //It's always good practice to refer to a generic type by specifying his specific type, by using Class<?> you're respecting this practice (you're aware of Class to be parameterizable) but you're not restricting your parameter to have a specific type.

    //isInstance ---> class level method
    private void ensureType(String registeredClaim, Object value, Class<?> expectedType) {
        boolean isCorrectType = expectedType.isInstance(value) || expectedType == Long.class && value instanceof Integer;

        if (!isCorrectType) {
            String msg = "Expected type: " + expectedType.getCanonicalName() + " for registered claim: '" + registeredClaim + "', but got value: " + value + " of type: " + value.getClass()
                    .getCanonicalName();
            throw new JwtException(msg);
        }
    }

    private void throwExceptionIfMotorcycleIsFalse(Object value) {
        if(value.equals(false)){
            throw new JwtException("Motorcycle is false for this request and that is not allowed!");
        }
    }

}
