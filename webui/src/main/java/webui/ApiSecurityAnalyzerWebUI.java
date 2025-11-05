package webui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Main entry point for API Security Analyzer Web UI.
 * Uses Spring Boot 4 - full support for Java 25.
 *
 * <p>Features:
 * <ul>
 *   <li>Interactive configuration with scanner selection</li>
 *   <li>Real-time log streaming</li>
 *   <li>Result visualization and export</li>
 *   <li>Full integration with core analysis engine</li>
 * </ul>
 *
 * <p>To run: java -jar webui/target/api-security-analyzer-webui.jar
 * <br>Access at: http://localhost:8080
 */
@SpringBootApplication
public class ApiSecurityAnalyzerWebUI {

    public static void main(String[] args) {
        System.out.println("\n=================================================");
        System.out.println("  API Security Analyzer WebUI");
        System.out.println("  Running on Java " + System.getProperty("java.version"));
        System.out.println("  Spring Boot 4.0.0-RC1 with Java 25 support");
        System.out.println("=================================================\n");

        SpringApplication.run(ApiSecurityAnalyzerWebUI.class, args);
    }

    /**
     * Configure Jackson ObjectMapper for JSON serialization.
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        return mapper;
    }

    /**
     * Configure CORS to allow requests from any origin.
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("*");
            }
        };
    }
}
