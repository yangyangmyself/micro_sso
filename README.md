## 单点登录升级改，技术栈Oauth2+springboot+security
*安装部署：*
* 启动服务后，将项目中certs目下的客户端证书jcbk_client导入浏览器`个人证书里`<br>
* 访问http://localhost:8443<br>

*改造要求：*
* 支持普通用户登录/证书登录<br>
* OAuth2 code自定义管理，目前采用存取redis，用于集群跨节点生成token<br>
* Token 可以自定义，添加额外属性，如支持kong<br>
* 后端接口支持以json及页面跳转方式返回code<br>
* 前端密码传递后端采用RSA加密传输<br>

### 一、启用Https、Http

`application.yml`配置SSL`双向认证`，其它配置省略，`https`端口为`8443`,`http`端口为`8066`<br>
* 服务器认证证书配置
```
server.ssl.key-store: classpath:jcbk.jks
server.ssl.key-store-password: 123456
server.ssl.keyStoreType: JKS
server.ssl.key-alias: jcbk
```
* 客户端信任证书配置
```
server.ssl.trust-store: classpath:jcbk.jks
server.ssl.trust-store-password: 123456
server.ssl.trust-store-type: JKS
```

* 所有配置如下述
```
server:
  port: 8443
  ssl:
    key-store: classpath:jcbk.jks
    key-store-password: 123456
    keyStoreType: JKS
    key-alias: jcbk
    trust-store: classpath:jcbk.jks
    trust-store-password: 123456
    trust-store-type: JKS
    client-auth: need
  http:
    port: 8066
```
* 启用http端口配置，`注意`下述适用`Sprintboot 1.X`, 引用初始类与Springboot 2.X有区别
```
package org.spring.oauth.server.config;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * 启用Https后,server.port默认用于启动https port
 * 如果需要同时启用http,需要启用本类配置
 * 注意:server.http.port为自定义属性
 * @author oyyl
 * @since 2020/6/23
 *
 */
@Component
public class EnabledHTTPConfiguration {
	
	//HTTP port
	@Value("${server.http.port}")
	private int httpPort;
	
	@Bean
	public EmbeddedServletContainerCustomizer customizeTomcatConnector() {
		return new EmbeddedServletContainerCustomizer() {
			@Override
			public void customize(ConfigurableEmbeddedServletContainer container) {
				if (container instanceof TomcatEmbeddedServletContainerFactory) {
					TomcatEmbeddedServletContainerFactory containerFactory = (TomcatEmbeddedServletContainerFactory) container;
					Connector connector = new Connector(TomcatEmbeddedServletContainerFactory.DEFAULT_PROTOCOL);
					connector.setPort(httpPort);
					containerFactory.addAdditionalTomcatConnectors(connector);
				}
			}
		};
	}
}
```

### 二、Spring security 安全体系概述

* 安全体系包括`认证`和`授权`两个方面，认证负责验证用户（即主体）是否正确合法；授权负责任检查请求的资源是否有权限访问
* 体系基于Filter过滤器实现，预定义默认过滤器，如HeaderWriterFilter、SecurityContextPersistenceFilter、X509AuthenticationFilter、UsernamePasswordAuthenticationFilter等，预定义过滤器基本满足日常开发，特殊情况下才需要自定义过滤器。
* 核心组件SecurityBuilder、SecurityConfigurer、FilterSecurityInterceptor、AbstractSecurityInterceptor
* SecurityConfigurer可以组件化方式扩展，主要组织AuthenticationProvider、UserDetailsService、Filter实现类；SecurityBuilder负责任SecurityConfigurer、Filter注册，HttpSecurity最为代表实现SecurityBuilder接口

### 三、PKI认证两种实现
#### 第1种实现
* 继承AbstractPreAuthenticatedProcessingFilter、实现AuthenticationProvider、UserDetailsService
* `PKIAuthenticationFilter`获取证书主体，用于父类构建PreAuthenticatedAuthenticationToken对象，`AuthenticationProvider`提供给`AuthenticationManager`认证，`UserDetailsService`提供具体主体获取，需要注入AuthenticationProvider对象中
* 将自定类注入Spring security体系结构中

`PKIAuthenticationFilter`类实现证书认证通过以后，提取证书`Principal`即主体，需要向父类提供AuthenticationManager对象
```
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

```
父类`AbstractPreAuthenticatedProcessingFilter`根据子类提供的实现，调用doAuthenticate方法构建PreAuthenticatedAuthenticationToken，用于`身份认证`Authentication

```
public abstract class AbstractPreAuthenticatedProcessingFilter extends GenericFilterBean
		implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher = null;
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private AuthenticationManager authenticationManager = null;
	private boolean continueFilterChainOnUnsuccessfulAuthentication = true;
	private boolean checkForPrincipalChanges;
	private boolean invalidateSessionOnPrincipalChange = true;
	private AuthenticationSuccessHandler authenticationSuccessHandler = null;
	private AuthenticationFailureHandler authenticationFailureHandler = null;

	/**
	 * Check whether all required properties have been set.
	 */
	@Override
	public void afterPropertiesSet() {
		try {
			super.afterPropertiesSet();
		}
		catch (ServletException e) {
			// convert to RuntimeException for passivity on afterPropertiesSet signature
			throw new RuntimeException(e);
		}
		Assert.notNull(authenticationManager, "An AuthenticationManager must be set");
	}

	/**
	 * Try to authenticate a pre-authenticated user with Spring Security if the user has
	 * not yet been authenticated.
	 */
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		if (logger.isDebugEnabled()) {
			logger.debug("Checking secure context token: "
					+ SecurityContextHolder.getContext().getAuthentication());
		}

		if (requiresAuthentication((HttpServletRequest) request)) {
			doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);
		}

		chain.doFilter(request, response);
	}

	/**
	 * Determines if the current principal has changed. The default implementation tries
	 *
	 * <ul>
	 * <li>If the {@link #getPreAuthenticatedPrincipal(HttpServletRequest)} is a String, the {@link Authentication#getName()} is compared against the pre authenticated principal</li>
	 * <li>Otherwise, the {@link #getPreAuthenticatedPrincipal(HttpServletRequest)} is compared against the {@link Authentication#getPrincipal()}
	 * </ul>
	 *
	 * <p>
	 * Subclasses can override this method to determine when a principal has changed.
	 * </p>
	 *
	 * @param request
	 * @param currentAuthentication
	 * @return true if the principal has changed, else false
	 */
	protected boolean principalChanged(HttpServletRequest request, Authentication currentAuthentication) {

		Object principal = getPreAuthenticatedPrincipal(request);

		if ((principal instanceof String) && currentAuthentication.getName().equals(principal)) {
			return false;
		}

		if (principal != null && principal.equals(currentAuthentication.getPrincipal())) {
			return false;
		}

		if(logger.isDebugEnabled()) {
			logger.debug("Pre-authenticated principal has changed to " + principal + " and will be reauthenticated");
		}
		return true;
	}

	/**
	 * Do the actual authentication for a pre-authenticated user.
	 */
	private void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		Authentication authResult;

		Object principal = getPreAuthenticatedPrincipal(request);
		Object credentials = getPreAuthenticatedCredentials(request);

		if (principal == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No pre-authenticated principal found in request");
			}

			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("preAuthenticatedPrincipal = " + principal
					+ ", trying to authenticate");
		}

		try {
			PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(
					principal, credentials);
			authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
			authResult = authenticationManager.authenticate(authRequest);
			successfulAuthentication(request, response, authResult);
		}
		catch (AuthenticationException failed) {
			unsuccessfulAuthentication(request, response, failed);

			if (!continueFilterChainOnUnsuccessfulAuthentication) {
				throw failed;
			}
		}
	}
}
```

AuthenticationProvider 实现类`SSLAuthenticationProvider`，依赖UserDetailsService对象注入
```
package org.spring.oauth.server.service;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * 入口为类AbstractPreAuthenticatedProcessingFilter(默认过滤器)
 * 自定义提供AuthenticationProvider实现类,Authentication实现类为PreAuthenticatedAuthenticationToken
 * 通过{@code org.spring.oauth.server.config.WebSecurityConfig.configureGlobal(AuthenticationManagerBuilder auth)}
 * 方法将SSLAuthenticationProvider注入AuthenticationManager实现类ProviderManager提供认证 
 * @author oyyl
 * @since 2020/06/30
 * {@code PreAuthenticatedAuthenticationProvider}
 * {@code AbstractUserDetailsAuthenticationProvider}
 * {@code DaoAuthenticationProvider}
 * {@code PreAuthenticatedAuthenticationToken}
 * {@code AbstractPreAuthenticatedProcessingFilter}
 *
 */
@Component("sslAuthenticationProvider")
public class SSLAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	@Qualifier("sslUserDetailsService")
	private UserDetailsService sslUserDetailsService;

	private final Logger logger = org.slf4j.LoggerFactory.getLogger(getClass());
	private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
	private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private boolean throwExceptionWhenTokenRejected = false;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("PreAuthenticated authentication request: " + authentication);
		}

		if (authentication.getPrincipal() == null) {
			logger.debug("No pre-authenticated principal found in request.");

			if (throwExceptionWhenTokenRejected) {
				throw new BadCredentialsException(
						"No pre-authenticated principal found in request.");
			}
			return null;
		}

		if (authentication.getCredentials() == null) {
			logger.debug("No pre-authenticated credentials found in request.");

			if (throwExceptionWhenTokenRejected) {
				throw new BadCredentialsException(
						"No pre-authenticated credentials found in request.");
			}
			return null;
		}
		
		// Determine username
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
		UserDetails user = null;
		try {
			user = this.sslUserDetailsService.loadUserByUsername(username);
		} catch (UsernameNotFoundException notFound) {
			logger.debug("User '" + username + "' not found");
			throw new BadCredentialsException(
					messages.getMessage("SSLAuthenticationProvider.badCredentials", "Bad credentials"));
		}
		Assert.notNull(user, "loadUserByUsername returned null - a violation of the interface contract");
		try {
			preAuthenticationChecks.check(user);
		}catch (AuthenticationException exception) {
			throw exception;
		}
		postAuthenticationChecks.check(user);

		PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(
				user, authentication.getCredentials(), user.getAuthorities());
		result.setDetails(authentication.getDetails());

		return result;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication));
	}
	
	private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
		public void check(UserDetails user) {
			if (!user.isAccountNonLocked()) {
				logger.debug("User account is locked");

				throw new LockedException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.locked",
						"User account is locked"));
			}

			if (!user.isEnabled()) {
				logger.debug("User account is disabled");

				throw new DisabledException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.disabled",
						"User is disabled"));
			}

			if (!user.isAccountNonExpired()) {
				logger.debug("User account is expired");

				throw new AccountExpiredException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.expired",
						"User account has expired"));
			}
		}
	}

	private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
		public void check(UserDetails user) {
			if (!user.isCredentialsNonExpired()) {
				logger.debug("User account credentials have expired");

				throw new CredentialsExpiredException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.credentialsExpired",
						"User credentials have expired"));
			}
		}
	}
}

```

获取用户获取服务`UserDetailsService`实现类

```
package org.spring.oauth.server.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spring.oauth.server.dao.PermissionDao;
import org.spring.oauth.server.dao.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
/**
 * @author oy
 * 
 */
@Service("sslUserDetailsService")
public class SSLSystemUserDetailsService implements UserDetailsService {

	protected Logger log = LoggerFactory.getLogger(getClass());

	@Autowired
	private UserDao userDao; // 具体Dao

	@Autowired
	private PermissionDao permissionDao;

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		Map map = userDao.findByID(username);
		if (map != null) {
			List permissions = getAuthorities(map.get("yhdh").toString());
			return new User(map.get("yhdh").toString(), map.get("mm")
					.toString(), permissions);
		} else {
			throw new UsernameNotFoundException("admin: " + username
					+ " do not exist!");
		}
	}

	private List<GrantedAuthority> getAuthorities(String yhdh) {
		List permissions = permissionDao.findPermissionById(yhdh);
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (Object permission : permissions) {
			Map map = (Map)permission;
			if (permission != null && map.get("role") != null) {
				GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(
						map.get("role").toString());
				// 1：此处将权限信息添加到 GrantedAuthority
				// 对象中，在后面进行全权限验证时会使用GrantedAuthority对象
				grantedAuthorities.add(grantedAuthority);
			}
		}
		return grantedAuthorities;
	}
}

```









