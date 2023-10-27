/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Base class that allows access to the {@link UserDetailsService} for using as a default
 * value with {@link AuthenticationManagerBuilder}.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder}
 * @param <U> the type of {@link UserDetailsService}
 * @author Rob Winch
 *
 * UserDetailsAwareConfigurer继承自SecurityConfigurerAdapter，
 * 这里泛型的第一个参数是AuthenticationManager，第二个参数是ProviderManagerBuilder类型，
 * 从泛型继承关系则可以看出该类的目的是使用ProviderManagerBuilder去构建AuthenticationManager
 *
 * 从继承关系可以看出
 * 1. 使用ProviderManagerBuidler构建AuthenticationManager
 * 2. 为子类扩展了getUserDetailsService的能力，返回值为UserDetailsService类型，代表数据源
 *
 */
public abstract class UserDetailsAwareConfigurer<B extends ProviderManagerBuilder<B>, U extends UserDetailsService>
		extends SecurityConfigurerAdapter<AuthenticationManager, B> {

	/**
	 * Gets the {@link UserDetailsService} or null if it is not available
	 * @return the {@link UserDetailsService} or null if it is not available
	 */
	public abstract U getUserDetailsService();

}
