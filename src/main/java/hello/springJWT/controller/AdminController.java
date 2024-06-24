package hello.springJWT.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class AdminController {

    @GetMapping("/admin")
    public String adminHome() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        return "admin home page" + name;
    }
}
