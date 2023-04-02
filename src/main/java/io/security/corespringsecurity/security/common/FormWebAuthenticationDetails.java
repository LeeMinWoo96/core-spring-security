package io.security.corespringsecurity.security.common;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

//    이 secret_key 이름으로 클라이언트에서 필터를 걸처 detailssource에 보내오면
//    detailssource 에서 details 객체를 생성하여 저장함
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }
}
