package com.kdt.prmgs.springsec.user;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    @Column(name ="id")
    private long id;

    @Column(name = "name")
    private String name;

    public long getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    @Override
    public String toString() {
        return "Permission{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
