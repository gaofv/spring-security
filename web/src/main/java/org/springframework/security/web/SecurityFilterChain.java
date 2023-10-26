/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

/**
 * Defines a filter chain which is capable of being matched against an
 * {@code HttpServletRequest}. in order to decide whether it applies to that request.
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 * @since 3.1
 *
 * SecurityFilterChain就是Spring Security的过滤器对象
 */
public interface SecurityFilterChain {

	/**
	 * 判断request请求是否应该被当前过滤器链处理
	 * @param request
	 * @return
	 */
	boolean matches(HttpServletRequest request);

	/**
	 * 方法返回一个过滤器集合，如果matches返回true，那么request就会在getFilters返回的所有过滤器中处理
	 * @return
	 */
	List<Filter> getFilters();

}
