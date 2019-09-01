package io.sanitizer.html_sanitizer;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
    	String sb = Sanitizer.sanitize("<p>alert(1);</p>");
    	System.out.println(sb);
    }
}
