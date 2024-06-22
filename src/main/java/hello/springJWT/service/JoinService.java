package hello.springJWT.service;

import hello.springJWT.common.Role;
import hello.springJWT.domain.Member;
import hello.springJWT.dto.MemberDto;
import hello.springJWT.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class JoinService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void createMember(MemberDto.Join memberJoinDto) {
        Boolean exists = memberRepository.existsByUsername(memberJoinDto.getUsername());

        if (exists) {
            return;
        }

        Member member = Member.createMember(memberJoinDto.getUsername(),
                bCryptPasswordEncoder.encode(memberJoinDto.getPassword()),
                Role.ROLE_USER);

        memberRepository.save(member);
    }
}
