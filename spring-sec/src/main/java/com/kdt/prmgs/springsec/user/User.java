package com.kdt.prmgs.springsec.user;

import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id")
    private long id;

    @Column(name = "login_id")
    private String loginId;

    @Column(name = "passwd")
    private String passWd;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    public void checkPassword(PasswordEncoder passwordEncoder, String credentials) {

        if (!passwordEncoder.matches(credentials, passWd)) {
            throw new IllegalArgumentException("Bad credentials");
        }
    }

    public long getId() {

        return id;
    }

    public String getLoginId() {

        return loginId;
    }

    public String getPassWd() {

        return passWd;
    }

    public Group getGroup() {

        return group;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", loginId='" + loginId + '\'' +
                ", passWd='" + passWd + '\'' +
                ", group=" + group +
                '}';
    }
}
