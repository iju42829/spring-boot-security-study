package hello.springJWT.dto;

import lombok.Getter;
import lombok.Setter;

public class MemberDto {

    @Getter @Setter
    public static class Join {
        private String username;
        private String password;
    }
}
