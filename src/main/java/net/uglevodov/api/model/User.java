package net.uglevodov.api.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

@Table("users")
@Data
public class User {

    @Id
    private Long id;
    private String username;
    private String password;
    private UserRole role;

}