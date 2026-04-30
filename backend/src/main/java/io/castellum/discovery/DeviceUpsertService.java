package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Separately-injected {@code @Service} that persists a single {@link Discovery}
 * observation into the {@link Device} inventory.
 *
 * <p>The {@code @Transactional} annotation is on the public {@link #upsert(Discovery)}
 * method only. No private helpers call {@code this.upsert(...)} — the proxy self-invocation
 * hazard is structurally avoided.
 *
 * <p>Upsert logic:
 * <ul>
 *   <li>Primary key: {@code ipAddress} (UNIQUE column).</li>
 *   <li>Existing row: update {@code lastSeen}; fill {@code macAddress} and {@code hostname}
 *       only if the existing values are {@code null}.</li>
 *   <li>New row: create with {@link Criticality#MEDIUM} default.</li>
 * </ul>
 */
@Service
public class DeviceUpsertService {

    private final DeviceRepository repo;

    public DeviceUpsertService(DeviceRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public Device upsert(Discovery d) {
        Optional<Device> existing = repo.findByIpAddress(d.ipAddress());
        if (existing.isPresent()) {
            Device e = existing.get();
            e.setLastSeen(d.observedAt());
            if (e.getMacAddress() == null && d.macAddress() != null) {
                e.setMacAddress(d.macAddress());
            }
            if (e.getHostname() == null && d.hostname() != null) {
                e.setHostname(d.hostname());
            }
            return repo.save(e);
        } else {
            Instant now = d.observedAt();
            Device fresh = new Device(
                null,
                d.ipAddress(),
                d.hostname(),
                d.macAddress(),
                now,
                now,
                Criticality.MEDIUM
            );
            return repo.save(fresh);
        }
    }

    /**
     * Batch counterpart to {@link #upsert(Discovery)}. Issues exactly one
     * {@link DeviceRepository#findByIpAddressIn} (read) plus one or two {@code saveAll}
     * calls (insert + update lists, kept separate so {@code hibernate.order_inserts}
     * can batch each homogeneous list cleanly).
     *
     * <p>Returns devices in the same order as the input list, so callers can correlate
     * {@code deviceIds} with their original {@link Discovery} sequence.
     *
     * @param discoveries unique-by-IP discoveries (callers should dedupe upstream)
     * @return persisted devices in input order
     */
    @Transactional
    public List<Device> upsertAll(List<Discovery> discoveries) {
        if (discoveries == null || discoveries.isEmpty()) {
            return List.of();
        }

        Set<String> ipSet = new HashSet<>();
        for (Discovery d : discoveries) {
            ipSet.add(d.ipAddress());
        }

        Map<String, Device> existingByIp = new HashMap<>();
        for (Device d : repo.findByIpAddressIn(ipSet)) {
            existingByIp.put(d.getIpAddress(), d);
        }

        List<Device> updates = new ArrayList<>();
        List<Device> inserts = new ArrayList<>();
        // Track which list each input maps to so we can return in input order
        // after both saveAll calls have run (and inserts have IDs assigned).
        record Slot(boolean isUpdate, int idx) {}
        List<Slot> slots = new ArrayList<>(discoveries.size());

        for (Discovery d : discoveries) {
            Device existing = existingByIp.get(d.ipAddress());
            if (existing != null) {
                existing.setLastSeen(d.observedAt());
                if (existing.getMacAddress() == null && d.macAddress() != null) {
                    existing.setMacAddress(d.macAddress());
                }
                if (existing.getHostname() == null && d.hostname() != null) {
                    existing.setHostname(d.hostname());
                }
                slots.add(new Slot(true, updates.size()));
                updates.add(existing);
            } else {
                Instant now = d.observedAt();
                Device fresh = new Device(null, d.ipAddress(), d.hostname(), d.macAddress(),
                    now, now, Criticality.MEDIUM);
                slots.add(new Slot(false, inserts.size()));
                inserts.add(fresh);
            }
        }

        List<Device> savedUpdates = updates.isEmpty() ? List.of() : repo.saveAll(updates);
        List<Device> savedInserts = inserts.isEmpty() ? List.of() : repo.saveAll(inserts);

        List<Device> result = new ArrayList<>(discoveries.size());
        for (Slot s : slots) {
            result.add(s.isUpdate() ? savedUpdates.get(s.idx()) : savedInserts.get(s.idx()));
        }
        return result;
    }
}
