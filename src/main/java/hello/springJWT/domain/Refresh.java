package hello.springJWT.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@Getter @Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Refresh {

    @Id
    @GeneratedValue
    @Column(name = "refresh_id")
    private Long id;

    private String username;

    private String refreshToken;

    private String expiration;

    private Refresh(String username, String refreshToken, String expiration) {
        this.username = username;
        this.refreshToken = refreshToken;
        this.expiration = expiration;
    }

    public static Refresh createRefresh(String username, String refreshToken, String expiration) {
        return new Refresh(username, refreshToken, expiration);
    }
}
