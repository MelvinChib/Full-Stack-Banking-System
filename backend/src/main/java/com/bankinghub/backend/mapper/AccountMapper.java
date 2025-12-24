package com.bankinghub.backend.mapper;

import com.bankinghub.backend.dto.request.AccountRequestDTO;
import com.bankinghub.backend.dto.response.AccountResponseDTO;
import com.bankinghub.backend.model.Account;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface AccountMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "accountNumber", ignore = true) // Will be generated
    @Mapping(target = "balance", source = "initialBalance")
    @Mapping(target = "active", constant = "true")
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "createdBy", ignore = true)
    @Mapping(target = "lastModifiedBy", ignore = true)
    @Mapping(target = "user", ignore = true) // Will be set in service
    @Mapping(target = "transactions", ignore = true)
    @Mapping(target = "fromTransfers", ignore = true)
    @Mapping(target = "toTransfers", ignore = true)
    Account toEntity(AccountRequestDTO dto);

    @Mapping(target = "maskedAccountNumber", ignore = true) // Calculated in DTO
    @Mapping(target = "availableBalance", ignore = true) // Calculated in DTO
    AccountResponseDTO toResponseDTO(Account account);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "accountNumber", ignore = true)
    @Mapping(target = "balance", ignore = true) // Balance shouldn't be updated via DTO
    @Mapping(target = "active", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "createdBy", ignore = true)
    @Mapping(target = "lastModifiedBy", ignore = true)
    @Mapping(target = "user", ignore = true)
    @Mapping(target = "transactions", ignore = true)
    @Mapping(target = "fromTransfers", ignore = true)
    @Mapping(target = "toTransfers", ignore = true)
    void updateEntityFromDTO(AccountRequestDTO dto, @MappingTarget Account account);
}