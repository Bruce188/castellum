package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.time.OffsetDateTime;

@Configuration
public class StixObjectMapperFactory {

    /**
     * Defining a typed {@link ObjectMapper} bean below disables Spring Boot's
     * {@code JacksonAutoConfiguration#jacksonObjectMapper} (which is gated on
     * {@code @ConditionalOnMissingBean(ObjectMapper.class)}). Without an explicit
     * primary, the Spring MVC message converter would resolve to the STIX-tuned
     * mapper — propagating {@code Include.NON_NULL} to every controller response
     * and dropping legitimately-null fields (e.g. {@code HopDto.edgeType}). This
     * primary bean restores the framework default so only callers that
     * {@code @Qualifier("stixObjectMapper")}-inject the STIX mapper see its
     * configuration.
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
        return builder.build();
    }

    @Bean(name = "stixObjectMapper")
    public ObjectMapper stixObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        SimpleModule zuluModule = new SimpleModule();
        zuluModule.addSerializer(OffsetDateTime.class, new StixZuluOffsetDateTimeSerializer());
        mapper.registerModule(new JavaTimeModule());
        mapper.registerModule(zuluModule);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return mapper;
    }
}
