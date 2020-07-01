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
	
	//=============================Below is other configuration===================================
	
	/**
	 * Notice Spring boot less 2.0 use TomcatEmbeddedServletContainerFactory
	 * @param connector
	 * @return
	 */
    /*@Bean
    public TomcatEmbeddedServletContainerFactory tomcatServletWebServerFactory(Connector connector) {
		TomcatEmbeddedServletContainerFactory tomcat = new TomcatEmbeddedServletContainerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        tomcat.addAdditionalTomcatConnectors(httpConnector());
        return tomcat;
    }	
    
	private Connector httpConnector() {
		Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
		connector.setScheme("http");
		// Connector监听的http的端口号
		connector.setPort(8066);
		connector.setSecure(false);
		// 监听到http的端口号后转向到的https的端口号
		//connector.setRedirectPort(8443);
		return connector;
	}*/
}
