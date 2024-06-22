package hello.springJWT.controller;

import hello.springJWT.dto.MemberDto;
import hello.springJWT.service.JoinService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinMember(@ModelAttribute MemberDto.Join memberJoinDto) {
        joinService.createMember(memberJoinDto);

        return "success";
    }

}
