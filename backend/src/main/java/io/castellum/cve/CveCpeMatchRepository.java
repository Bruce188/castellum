package io.castellum.cve;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface CveCpeMatchRepository extends JpaRepository<CveCpeMatch, Long> {

    List<CveCpeMatch> findByCpe23Uri(String cpe);

    List<CveCpeMatch> findByCpe23UriStartingWithOrderByIdAsc(String prefix);

    List<CveCpeMatch> findByCveFk(Long cveFk);

    @Modifying
    @Transactional
    void deleteByCveFk(Long cveFk);
}
