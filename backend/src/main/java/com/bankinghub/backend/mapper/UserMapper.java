package com.bankinghub.backend.mapper;

import com.bankinghub.backend.dto.request.UserRequestDTO;
import com.bankinghub.backend.dto.response.UserResponseDTO;
import com.bankinghub.backend.model.User;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "enabled", constant = "true")
    @Mapping(target = "accountNonExpired", constant = "true")
    @Mapping(target = "accountNonLocked", constant = "true")
    @Mapping(target = "credentialsNonExpired", constant = "true")
    @Mapping(target = "role", constant = "USER")
    @Mapping(target = "twoFactorEnabled", constant = "false")
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "twoFactorSecret", ignore = true)
    @Mapping(target = "accounts", ignore = true)
    @Mapping(target = "bills", ignore = true)
    @Mapping(target = "budgets", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "createdBy", ignore = true)
    @Mapping(target = "lastModifiedBy", ignore = true)
    User toEntity(UserRequestDTO dto);

    UserResponseDTO toResponseDTO(User user);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "accountNonExpired", ignore = true)
    @Mapping(target = "accountNonLocked", ignore = true)
    @Mapping(target = "credentialsNonExpired", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "twoFactorEnabled", ignore = true)
    @Mapping(target = "twoFactorSecret", ignore = true)
    @Mapping(target = "accounts", ignore = true)
    @Mapping(target = "bills", ignore = true)
    @Mapping(target = "budgets", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "createdBy", ignore = true)
    @Mapping(target = "lastModifiedBy", ignore = true)
    void updateEntityFromDTO(UserRequestDTO dto, @MappingTarget User user);
}