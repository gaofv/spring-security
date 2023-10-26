/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.firewall.DefaultRequestRejectedHandler;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Delegates {@code Filter} requests to a list of Spring-managed filter beans. As of
 * version 2.0, you shouldn't need to explicitly configure a {@code FilterChainProxy} bean
 * in your application context unless you need very fine control over the filter chain
 * contents. Most cases should be adequately covered by the default
 * {@code <security:http />} namespace configuration options.
 * <p>
 * The {@code FilterChainProxy} is linked into the servlet container filter chain by
 * adding a standard Spring {@link DelegatingFilterProxy} declaration in the application
 * {@code web.xml} file.
 *
 * <h2>Configuration</h2>
 * <p>
 * As of version 3.1, {@code FilterChainProxy} is configured using a list of
 * {@link SecurityFilterChain} instances, each of which contains a {@link RequestMatcher}
 * and a list of filters which should be applied to matching requests. Most applications
 * will only contain a single filter chain, and if you are using the namespace, you don't
 * have to set the chains explicitly. If you require finer-grained control, you can make
 * use of the {@code <filter-chain>} namespace element. This defines a URI pattern and the
 * list of filters (as comma-separated bean names) which should be applied to requests
 * which match the pattern. An example configuration might look like this:
 *
 * <pre>
 *  &lt;bean id="myfilterChainProxy" class="org.springframework.security.web.FilterChainProxy"&gt;
 *      &lt;constructor-arg&gt;
 *          &lt;util:list&gt;
 *              &lt;security:filter-chain pattern="/do/not/filter*" filters="none"/&gt;
 *              &lt;security:filter-chain pattern="/**" filters="filter1,filter2,filter3"/&gt;
 *          &lt;/util:list&gt;
 *      &lt;/constructor-arg&gt;
 *  &lt;/bean&gt;
 * </pre>
 *
 * The names "filter1", "filter2", "filter3" should be the bean names of {@code Filter}
 * instances defined in the application context. The order of the names defines the order
 * in which the filters will be applied. As shown above, use of the value "none" for the
 * "filters" can be used to exclude a request pattern from the security filter chain
 * entirely. Please consult the security namespace schema file for a full list of
 * available configuration options.
 *
 * <h2>Request Handling</h2>
 * <p>
 * Each possible pattern that the {@code FilterChainProxy} should service must be entered.
 * The first match for a given request will be used to define all of the {@code Filter}s
 * that apply to that request. This means you must put most specific matches at the top of
 * the list, and ensure all {@code Filter}s that should apply for a given matcher are
 * entered against the respective entry. The {@code FilterChainProxy} will not iterate
 * through the remainder of the map entries to locate additional {@code Filter}s.
 * <p>
 * {@code FilterChainProxy} respects normal handling of {@code Filter}s that elect not to
 * call
 * {@link javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
 * , in that the remainder of the original or {@code FilterChainProxy}-declared filter
 * chain will not be called.
 *
 * <h3>Request Firewalling</h3>
 *
 * An {@link HttpFirewall} instance is used to validate incoming requests and create a
 * wrapped request which provides consistent path values for matching against. See
 * {@link StrictHttpFirewall}, for more information on the type of attacks which the
 * default implementation protects against. A custom implementation can be injected to
 * provide stricter control over the request contents or if an application needs to
 * support certain types of request which are rejected by default.
 * <p>
 * Note that this means that you must use the Spring Security filters in combination with
 * a {@code FilterChainProxy} if you want this protection. Don't define them explicitly in
 * your {@code web.xml} file.
 * <p>
 * {@code FilterChainProxy} will use the firewall instance to obtain both request and
 * response objects which will be fed down the filter chain, so it is also possible to use
 * this functionality to control the functionality of the response. When the request has
 * passed through the security filter chain, the {@code reset} method will be called. With
 * the default implementation this means that the original values of {@code servletPath}
 * and {@code pathInfo} will be returned thereafter, instead of the modified ones used for
 * security pattern matching.
 * <p>
 * Since this additional wrapping functionality is performed by the
 * {@code FilterChainProxy}, we don't recommend that you use multiple instances in the
 * same filter chain. It shouldn't be considered purely as a utility for wrapping filter
 * beans in a single {@code Filter} instance.
 *
 * <h2>Filter Lifecycle</h2>
 * <p>
 * Note the {@code Filter} lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} Javadocs, we recommend you
 * allow the IoC container to manage the lifecycle instead of the servlet container.
 * {@code FilterChainProxy} does not invoke the standard filter lifecycle methods on any
 * filter beans that you add to the application context.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 *
 *
 *
 * Spring Security Filter 并不是直接嵌入到 Web Filter 中的，而是通过 FilterChainProxy 来统一管理 Spring Security Filter，
 * FilterChainProxy 本身则通过 Spring 提供的 DelegatingFilterProxy 代理过滤器嵌入到 Web Filter 之中。
 */
public class FilterChainProxy extends GenericFilterBean {

	private static final Log logger = LogFactory.getLog(FilterChainProxy.class);
	/**
	 * 标记过滤器是否已经执行过了
	 */
	private static final String FILTER_APPLIED = FilterChainProxy.class.getName().concat(".APPLIED");
	/**
	 * Spring Security过滤器链
	 */
	private List<SecurityFilterChain> filterChains;
	/**
	 * filterChainValidator 是 FilterChainProxy 配置完成后的校验方法，
	 * 默认使用的 NullFilterChainValidator 实际上对应了一个空方法，也就是不做任何校验。
	 */
	private FilterChainValidator filterChainValidator = new NullFilterChainValidator();
	/**
	 * 防火墙
	 */
	private HttpFirewall firewall = new StrictHttpFirewall();

	private RequestRejectedHandler requestRejectedHandler = new DefaultRequestRejectedHandler();

	private ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

	public FilterChainProxy() {
	}

	public FilterChainProxy(SecurityFilterChain chain) {
		this(Arrays.asList(chain));
	}

	public FilterChainProxy(List<SecurityFilterChain> filterChains) {
		this.filterChains = filterChains;
	}

	@Override
	public void afterPropertiesSet() {
		this.filterChainValidator.validate(this);
	}

	/**
	 * 在 doFilter 方法中，正常来说，clearContext 参数每次都是 true，
	 * 于是每次都先给 request 标记上 FILTER_APPLIED 属性，然后执行 doFilterInternal 方法去走过滤器，执行完毕后，
	 * 最后在 finally 代码块中清除 SecurityContextHolder 中保存的用户信息，同时移除 request 中的标记。
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (!clearContext) {
			doFilterInternal(request, response, chain);
			return;
		}
		try {
			request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
			doFilterInternal(request, response, chain);
		}
		catch (Exception ex) {
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			Throwable requestRejectedException = this.throwableAnalyzer
					.getFirstThrowableOfType(RequestRejectedException.class, causeChain);
			if (!(requestRejectedException instanceof RequestRejectedException)) {
				throw ex;
			}
			this.requestRejectedHandler.handle((HttpServletRequest) request, (HttpServletResponse) response,
					(RequestRejectedException) requestRejectedException);
		}
		finally {
			SecurityContextHolder.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
	}

	private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 首先将请求封装为一个 FirewalledRequest 对象，在这个封装的过程中，也会判断请求是否合法
		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
		// 对响应进行封装。
		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
		// 调用 getFilters 方法找到过滤器链。该方法就是根据当前的请求，
		// 从 filterChains 中找到对应的过滤器链，然后由该过滤器链去处理请求
		List<Filter> filters = getFilters(firewallRequest);
		// 如果找出来的 filters 为 null，或者集合中没有元素，那就是说明当前请求不需要经过过滤器。
		// 直接执行 chain.doFilter ，这个就又回到原生过滤器中去了。那么什么时候会发生这种情况呢？
		// 那就是针对项目中的静态资源，如果我们配置了资源放行，如 web.ignoring().antMatchers("/hello");，
		// 那么当你请求 /hello 接口时就会走到这里来，也就是说这个不经过 Spring Security Filter。
		if (filters == null || filters.size() == 0) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
			}
			firewallRequest.reset();
			chain.doFilter(firewallRequest, firewallResponse);
			return;
		}
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
		}
		// 如果查询到的 filters 中是有值的，那么这个 filters 集合中存放的就是我们要经过的过滤器链了。
		// 此时它会构造出一个虚拟的过滤器链 VirtualFilterChain 出来，并执行其中的 doFilter 方法。
		VirtualFilterChain virtualFilterChain = new VirtualFilterChain(firewallRequest, chain, filters);
		virtualFilterChain.doFilter(firewallRequest, firewallResponse);
	}

	/**
	 * Returns the first filter chain matching the supplied URL.
	 * @param request the request to match
	 * @return an ordered array of Filters defining the filter chain
	 */
	private List<Filter> getFilters(HttpServletRequest request) {
		int count = 0;
		for (SecurityFilterChain chain : this.filterChains) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
						this.filterChains.size()));
			}
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}
		return null;
	}

	/**
	 * Convenience method, mainly for testing.
	 * @param url the URL
	 * @return matching filter list
	 */
	public List<Filter> getFilters(String url) {
		return getFilters(this.firewall.getFirewalledRequest((new FilterInvocation(url, "GET").getRequest())));
	}

	/**
	 * @return the list of {@code SecurityFilterChain}s which will be matched against and
	 * applied to incoming requests.
	 */
	public List<SecurityFilterChain> getFilterChains() {
		return Collections.unmodifiableList(this.filterChains);
	}

	/**
	 * Used (internally) to specify a validation strategy for the filters in each
	 * configured chain.
	 * @param filterChainValidator the validator instance which will be invoked on during
	 * initialization to check the {@code FilterChainProxy} instance.
	 */
	public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
		this.filterChainValidator = filterChainValidator;
	}

	/**
	 * Sets the "firewall" implementation which will be used to validate and wrap (or
	 * potentially reject) the incoming requests. The default implementation should be
	 * satisfactory for most requirements.
	 * @param firewall
	 */
	public void setFirewall(HttpFirewall firewall) {
		this.firewall = firewall;
	}

	/**
	 * Sets the {@link RequestRejectedHandler} to be used for requests rejected by the
	 * firewall.
	 * @param requestRejectedHandler the {@link RequestRejectedHandler}
	 * @since 5.2
	 */
	public void setRequestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
		Assert.notNull(requestRejectedHandler, "requestRejectedHandler may not be null");
		this.requestRejectedHandler = requestRejectedHandler;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("FilterChainProxy[");
		sb.append("Filter Chains: ");
		sb.append(this.filterChains);
		sb.append("]");
		return sb.toString();
	}

	private static String requestLine(HttpServletRequest request) {
		return request.getMethod() + " " + UrlUtils.buildRequestUrl(request);
	}

	/**
	 * Internal {@code FilterChain} implementation that is used to pass a request through
	 * the additional internal list of filters which match the request.
	 */
	private static final class VirtualFilterChain implements FilterChain {
		/**
		 * 原生过滤器链，也就是Web Filter
		 */
		private final FilterChain originalChain;
		/**
		 * Spring Security过滤器链
		 */
		private final List<Filter> additionalFilters;
		/**
		 * 当前请求
		 */
		private final FirewalledRequest firewalledRequest;
		/**
		 * 过滤器链中的过滤器的个数
		 */
		private final int size;
		/**
		 * 过滤器链遍历时的下标
		 */
		private int currentPosition = 0;

		private VirtualFilterChain(FirewalledRequest firewalledRequest, FilterChain chain,
				List<Filter> additionalFilters) {
			this.originalChain = chain;
			this.additionalFilters = additionalFilters;
			this.size = additionalFilters.size();
			this.firewalledRequest = firewalledRequest;
		}

		/**
		 * doFilter 方法就是 Spring Security 中过滤器挨个执行的过程，如果 currentPosition == size，表示过滤器链已经执行完毕
		 * 此时通过调用 originalChain.doFilter 进入到原生过滤链方法中，同时也退出了 Spring Security 过滤器链。
		 * 否则就从 additionalFilters 取出 Spring Security 过滤器链中的一个个过滤器，挨个调用 doFilter 方法。
		 */
		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
				if (logger.isDebugEnabled()) {
					logger.debug(LogMessage.of(() -> "Secured " + requestLine(this.firewalledRequest)));
				}
				// Deactivate path stripping as we exit the security filter chain
				this.firewalledRequest.reset();
				this.originalChain.doFilter(request, response);
				return;
			}
			this.currentPosition++;
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", nextFilter.getClass().getSimpleName(),
						this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}

	}

	public interface FilterChainValidator {

		void validate(FilterChainProxy filterChainProxy);

	}

	private static class NullFilterChainValidator implements FilterChainValidator {

		@Override
		public void validate(FilterChainProxy filterChainProxy) {
		}

	}

}
