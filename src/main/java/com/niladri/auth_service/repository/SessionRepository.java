package com.niladri.auth_service.repository;

import com.niladri.auth_service.entity.Session;
import com.niladri.auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {
    List<Session> findByUser(User userDetails);

    Optional<Session> findByRefreshToken(String refreshToken);
}
