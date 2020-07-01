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
