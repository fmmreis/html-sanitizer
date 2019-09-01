package io.sanitizer.html_sanitizer;

import org.owasp.html.AttributePolicy;
import org.owasp.html.Handler;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamRenderer;

public class Sanitizer {
	  public static String sanitize(String html) {
		    StringBuilder sb = new StringBuilder();
		    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
		        sb,
		        new Handler<String>() {
		          public void handle(String errorMessage) {
		          }
		        });

		    HtmlSanitizer.Policy policy = new HtmlPolicyBuilder()
		        // Allow these tags.
		       .allowElements(
		           "a", "b", "br", "div", "i", "iframe", "img", "input", "li",
		           "ol", "p", "span", "ul", "noscript", "noframes", "noembed", "noxss")
		       // And these attributes.
		       .allowAttributes(
		           "dir", "checked", "class", "href", "id", "target", "title", "type")
		       .globally()
		       // Cleanup IDs and CLASSes and prefix them with p- to move to a separate
		       // name-space.
		       .allowAttributes("id", "class")
		       .matching(
		           new AttributePolicy() {
		            public String apply(
		                String elementName, String attributeName, String value) {
		              return value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
		                  .replaceAll("\\s+", " ")
		                  .trim();
		            }
		           })
		       .globally()
		       .allowStyling()
		       // Don't throw out useless <img> and <input> elements to ease debugging.
		       .allowWithoutAttributes("img", "input")
		       .build(renderer);

		    HtmlSanitizer.sanitize(html, policy);

		    return sb.toString();
		  }
}
