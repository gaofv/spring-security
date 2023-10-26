/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.lang.annotation.*;

/**
 * Add this annotation to an {@code @Configuration} class to have the Spring Security
 * configuration defined in any {@link WebSecurityConfigurer} or more likely by exposing a
 * {@link SecurityFilterChain} bean:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class MyWebSecurityConfiguration {
 *
 * 	&#064;Bean
 * 	public WebSecurityCustomizer webSecurityCustomizer() {
 * 		return (web) -> web.ignoring()
 * 		// Spring Security should completely ignore URLs starting with /resources/
 * 				.antMatchers(&quot;/resources/**&quot;);
 *    }
 *
 * 	&#064;Bean
 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 * 		http.authorizeRequests().antMatchers(&quot;/public/**&quot;).permitAll().anyRequest()
 * 				.hasRole(&quot;USER&quot;).and()
 * 				// Possibly more configuration ...
 * 				.formLogin() // enable form based log in
 * 				// set permitAll for all URLs associated with Form Login
 * 				.permitAll();
 * 		return http.build();
 *    }
 *
 * 	&#064;Bean
 * 	public UserDetailsService userDetailsService() {
 * 		UserDetails user = User.withDefaultPasswordEncoder()
 * 			.username(&quot;user&quot;)
 * 			.password(&quot;password&quot;)
 * 			.roles(&quot;USER&quot;)
 * 			.build();
 * 		UserDetails admin = User.withDefaultPasswordEncoder()
 * 			.username(&quot;admin&quot;)
 * 			.password(&quot;password&quot;)
 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
 * 			.build();
 * 		return new InMemoryUserDetailsManager(user, admin);
 *    }
 *
 * 	// Possibly more bean methods ...
 * }
 * </pre>
 *
 * @author Rob Winch
 * @see WebSecurityConfigurer
 * @since 3.2
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
/**
 * 导入了四个配置类
 * WebSecurityConfiguration：使用自定义WebSecurityConfigurer和WebSecurityCustomizer配置WebSecurity，并创建SecurityFilterChain
 * SpringWebMvcImportSelector：引入SpringMVC相关配置
 * OAuth2ImportSelector：引入OAuth2相关配置
 * HttpSecurityConfiguration：注入HttpSecurity
 */
@Import({WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class})
/**
 * 导入配置类AuthenticationConfiguration
 */
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

	/**
	 * Controls debugging support for Spring Security. Default is false.
	 *
	 * @return if true, enables debug support with Spring Security
	 */
	boolean debug() default false;

}
