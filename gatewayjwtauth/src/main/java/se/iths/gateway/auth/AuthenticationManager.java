package se.iths.gateway.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    private JWTUtil jwtUtil;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
        try {
            //Check if signed with our secret key
            var claims = jwtUtil.getAllClaimsFromToken(authToken);
            if (claims == null) {
                return Mono.empty();
            }
            //Check so it hasn't expired
            Date expires = claims.getBody().getExpiration();
            if( expires.before(new Date(System.currentTimeMillis())) )
                return Mono.empty();

            //Get list of roles for this user
            ArrayList<String> perms = (ArrayList<String>) claims.getBody().get("authorities");
            var authorities = perms.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            return Mono.just(new UsernamePasswordAuthenticationToken(claims.getBody().getSubject(), null, authorities));
        } catch (Exception e) {
            return Mono.empty();
        }
    }
}