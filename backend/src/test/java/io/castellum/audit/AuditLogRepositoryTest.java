package io.castellum.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class AuditLogRepositoryTest {

    @Autowired
    private AuditLogRepository repository;

    @Test
    void saveAndFindAll_returnsRow() {
        AuditLog log = new AuditLog(Instant.now(), "system", "TEST_ACTION", "device", "1", "{\"key\":\"value\"}");
        repository.save(log);

        List<AuditLog> all = repository.findAll();
        assertEquals(1, all.size());

        AuditLog found = all.get(0);
        assertEquals("system", found.getActor());
        assertEquals("TEST_ACTION", found.getAction());
        assertEquals("device", found.getResourceType());
        assertEquals("1", found.getResourceId());
    }

    @Test
    void auditLog_hasNoPublicSetters() {
        long setterCount = Stream.of(AuditLog.class.getMethods())
            .filter(m -> m.getName().startsWith("set") && m.getParameterCount() == 1)
            .count();
        assertEquals(0, setterCount, "AuditLog should have no public setters");
    }

    @Test
    void auditLogRepository_declaresNoDeleteMethods() {
        long deleteCount = Stream.of(AuditLogRepository.class.getMethods())
            .filter(m -> m.getName().startsWith("delete"))
            .count();
        assertEquals(0, deleteCount, "AuditLogRepository should declare no delete* methods");
    }
}
