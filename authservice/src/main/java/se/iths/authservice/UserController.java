package se.iths.authservice;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import se.iths.authservice.common.JwtConfig;
import se.iths.authservice.entities.User;

import java.sql.Date;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping()
public class UserController {

    private final UserRepository userRepository;
    private PasswordEncoder encoder;
    private final JwtConfig jwtConfig;

    public UserController(UserRepository userDetailsService, PasswordEncoder encoder, JwtConfig jwtConfig) {

        this.userRepository = userDetailsService;
        this.encoder = encoder;
        this.jwtConfig = jwtConfig;
    }

    @PostMapping("/sign-up")
    public void signUp(@RequestBody UserCredentials user) {
        if (userRepository.findByUsername(user.getUsername()) != null)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + user.getUsername() + " already exists.");

        User appUser = new User();
        appUser.setUsername(user.getUsername());
        appUser.setPassword(encoder.encode(user.getPassword()));
        appUser.setRoles("USER");
        userRepository.save(appUser);
    }

    @PostMapping("/auth")
    public TokenResponse auth(@RequestBody UserCredentials credentials) {
        User user = userRepository.findByUsername(credentials.getUsername());
        if (user == null)
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid user credentials");

        String existingPassword = credentials.getPassword();
        String dbPassword = user.getPassword();

        if (encoder.matches(existingPassword, dbPassword)) {
            List<GrantedAuthority> grantedAuthorities =
                    Arrays.stream(user.getRoles().split(","))
                            .map(s -> "ROLE_" + s)
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

            long now = System.currentTimeMillis();
            String token = Jwts.builder()
                    .setSubject(user.getUsername())
                    .setIssuedAt(new Date(now))
                    .setExpiration(new Date(now + jwtConfig.getExpiration() * 1000L))  // in milliseconds
                    .claim("authorities", grantedAuthorities.stream()
                            .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
                    .compact();

            var tokenInfo = new TokenResponse();
            tokenInfo.access_token = token;
            tokenInfo.token_type = jwtConfig.getPrefix();
            tokenInfo.expires_in = jwtConfig.getExpiration();
            return tokenInfo;
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid user credentials");
    }
}
