package hello.springJWT.domain;

import hello.springJWT.common.Role;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {
    @Id
    @GeneratedValue
    @Column(name = "member_id")
    public Long id;

    private String username;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private Member(String username, String password, Role role) {
        this.username = username;
        this.role = role;
        this.password = password;
    }

    public static Member createMember(String username, String password, Role role) {
        return new Member(username, password, role);
    }
}
