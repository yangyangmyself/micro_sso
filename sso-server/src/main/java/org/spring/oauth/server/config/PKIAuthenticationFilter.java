package org.spring.oauth.server.config;

import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.stereotype.Component;

/**
 * PKI登录,证书主体、凭证提取,用于构建PreAuthenticatedAuthenticationToken对象
 * 参考
 * {@link org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter}
 * {@link org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter}
 * @author oyyl
 * @since 2020/06/23
 * @version v0.1
 */
@Component("pkiAuthenticationFilter")
public class PKIAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter{
	
	@Autowired
	public AuthenticationManager authenticationManager; // 默认实现为ProviderManager
	
	@Autowired
	@Qualifier("sslUserDetailsService")
	private UserDetailsService sslUserDetailsService;
	
	private X509PrincipalExtractor principalExtractor = new DefinedSubjectDnX509PrincipalExtractor();
	
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		X509Certificate cert = extractClientCertificate(request);
		if (cert == null) {
			return null;
		}
		return principalExtractor.extractPrincipal(cert);
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return extractClientCertificate(request);
	}
	
	@Override
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		super.setAuthenticationManager(authenticationManager);
	}

	/**
	 * CN提取根据具体证书格式,通过正则表达式提取
	 * @param request
	 * @return
	 */
	private X509Certificate extractClientCertificate(HttpServletRequest request) {
		X509Certificate[] certs = (X509Certificate[]) request
				.getAttribute("javax.servlet.request.X509Certificate");
		if (certs != null && certs.length > 0) {
			if (logger.isDebugEnabled()) {
				logger.debug("X.509 客户端认证证书:" + certs[0]);
			}
			return certs[0];
		}
		if (logger.isDebugEnabled()) {
			logger.debug("请求未发现客户端证书!");
		}
		return null;
	}
	
	/**
	 * X509证书主体获取实现类(证书CN内容)
	 * @author oyyl
	 */
	private class DefinedSubjectDnX509PrincipalExtractor implements X509PrincipalExtractor{

		private Pattern subjectDnPattern = Pattern.compile("CN=(.*?)(?:,|$)", Pattern.CASE_INSENSITIVE);;
		
		@Override
		public Object extractPrincipal(X509Certificate clientCert) {
			// String subjectDN = clientCert.getSubjectX500Principal().getName();
			String subjectDN = clientCert.getSubjectDN().getName();
			
			logger.debug("证书DN为'" + subjectDN + "'");
			
			Matcher matcher = subjectDnPattern.matcher(subjectDN);

			if (!matcher.find()) {
				throw new BadCredentialsException("证书DN不匹配:" + subjectDN);
			}
			if (matcher.groupCount() != 1) {
				throw new IllegalArgumentException(
						"DN正则表达式只能单个Group");
			}

			String username = matcher.group(1);
			
			if(username!=null) username=username.split(" ")[1];
			
			logger.debug("证书提取到主体为 '" + username + "'");
			
			return username;
		}
	}

	@Override
	public void afterPropertiesSet() {
		setAuthenticationManager(authenticationManager);
	}
}
