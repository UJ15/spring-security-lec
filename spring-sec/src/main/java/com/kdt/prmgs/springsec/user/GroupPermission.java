package com.kdt.prmgs.springsec.user;

import javax.persistence.*;

@Entity
@Table(name = "group_permission")
public class GroupPermission {

    @Id
    @Column(name = "id")
    private long id;

    @JoinColumn(name = "group_id")
    @ManyToOne(optional = false)
    private Group group;

    @JoinColumn(name = "permission_id")
    @ManyToOne(optional = false)
    private Permission permission;

    public void setId(long id) {

        this.id = id;
    }

    public Group getGroup() {

        return group;
    }

    public Permission getPermission() {

        return permission;
    }

    @Override
    public String toString() {
        return "GroupPermission{" +
                "id=" + id +
                ", group=" + group +
                ", permission=" + permission +
                '}';
    }
}
