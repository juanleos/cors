package mx.org.inegi.ce.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import mx.org.inegi.ce.access.AllowedOrigin;
import mx.org.inegi.ce.access.AllowedOriginMaker;
import mx.org.inegi.ce.access.Origin;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Spring filter that adds headers to response as needed by CORS specification.
 * 
 * 
 */
public class CORSFilter extends OncePerRequestFilter implements Filter {

	private AllowedOriginMaker originMaker;

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		AllowedOrigin allowedOrigins = originMaker.getAllowedOrigin();
		String origin = request.getHeader("origin");
		String originToEcho = null;
		if (allowedOrigins.containsOrigin(origin)) {
			Origin o = allowedOrigins.get(origin);
			originToEcho = o.getUrl();
		}

		if (request.getMethod().equals("POST")
				|| request.getMethod().equals("GET")
				|| request.getMethod().equals("DELETE")
				|| request.getMethod().equals("PUT")
				|| request.getMethod().equals("OPTIONS")) {
			if (originToEcho != null)
				response.addHeader("Access-Control-Allow-Origin", originToEcho);
			response.addHeader("Access-Control-Allow-Credentials", "true");
		}

		if (request.getHeader("Access-Control-Request-Method") != null) {
			response.addHeader("Access-Control-Allow-Headers",
					"Origin, Content-Type, Accept, X-Requested-With");
			response.addHeader("Access-Control-Max-Age", "60");
			response.addHeader("Access-Control-Allow-Methods",
					"GET, POST, PUT, DELETE");
		}

		filterChain.doFilter(request, response);
	}

	public void setOriginMaker(AllowedOriginMaker originMaker) {
		this.originMaker = originMaker;
	}

}
