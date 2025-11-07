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
 * Точка входа в веб-интерфейс API Security Analyzer.
 * Использует Spring Boot 4 с полной поддержкой Java 25.
 *
 * <p>Возможности:
 * <ul>
 *   <li>Интерактивная настройка с выбором сканеров</li>
 *   <li>Потоковая передача логов в реальном времени</li>
 *   <li>Визуализация и экспорт результатов</li>
 *   <li>Полная интеграция с ядром анализа</li>
 * </ul>
 *
 * <p>Запуск: java -jar webui/target/api-security-analyzer-webui.jar
 * <br>Доступ: http://localhost:8080
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
     * Настройка Jackson ObjectMapper для сериализации JSON.
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
     * Настройка CORS для разработки с доступом с localhost.
     * В production необходимо настроить конкретные разрешенные источники через application.properties.
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins(
                            "http://localhost:3000",
                            "http://localhost:8080",
                            "http://127.0.0.1:3000",
                            "http://127.0.0.1:8080"
                        )
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }
}
