package com.niladri.auth_service.service;

import com.niladri.auth_service.entity.Session;
import com.niladri.auth_service.entity.User;
import com.niladri.auth_service.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final SessionRepository sessionRepository;
    private final int SESSION_LIMIT = 2;

    public void generateNewSession(User userDetails, String refreshToken) {

        //fetch all the sessions of the current user
        List<Session> sessions = sessionRepository.findByUser(userDetails);

        //if the limit is reached, then delete the least active session
        if (sessions.size() == SESSION_LIMIT) {
            // sort the sessions based on last active time
            sessions.sort(Comparator.comparing(Session::getLastActiveTime));

            // delete the least active session
            Session leastActiveSession = sessions.getFirst();
            sessionRepository.delete(leastActiveSession);
        }

        // create a new session
        Session newSession = Session.builder().user(userDetails).refreshToken(refreshToken).build();
        sessionRepository.save(newSession);
    }


    public void isSessionValid(String refreshToken) {



        Session session = sessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new SessionAuthenticationException("Session not found for refresh token" + refreshToken));
        //updating the last active time of the session to the current time for the current user

        log.info("Session last active time: {}", session.getLastActiveTime());
        session.setLastActiveTime(LocalDateTime.now());
        sessionRepository.save(session);
    }
}
