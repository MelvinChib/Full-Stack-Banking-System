package com.bankinghub.backend.service;

import com.bankinghub.backend.dto.request.AccountRequestDTO;
import com.bankinghub.backend.dto.response.AccountResponseDTO;
import com.bankinghub.backend.exception.CustomBusinessException;
import com.bankinghub.backend.exception.ResourceNotFoundException;
import com.bankinghub.backend.model.Account;
import com.bankinghub.backend.model.User;
import com.bankinghub.backend.repository.AccountRepository;
import com.bankinghub.backend.repository.UserRepository;
import com.bankinghub.backend.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private final AccountRepository accountRepository;
    private final UserRepository userRepository;
    
    @Value("${app.bank.account.number-prefix:MBZ}")
    private String accountNumberPrefix;

    @Transactional
    public AccountResponseDTO createAccount(AccountRequestDTO accountRequest) {
        User currentUser = getCurrentUser();
        log.debug("Creating account for user ID: {}", currentUser.getId());

        Account account = new Account();
        account.setUser(currentUser);
        account.setAccountType(accountRequest.getAccountType());
        account.setAccountName(accountRequest.getAccountName());
        account.setDescription(accountRequest.getDescription());
        account.setBalance(accountRequest.getInitialBalance());
        account.setCreditLimit(accountRequest.getCreditLimit());
        account.setInterestRate(accountRequest.getInterestRate());
        account.setAccountNumber(generateAccountNumber());

        Account savedAccount = accountRepository.save(account);
        log.info("Account created successfully with ID: {}", savedAccount.getId());

        return convertToAccountResponse(savedAccount);
    }

    @Transactional(readOnly = true)
    public List<AccountResponseDTO> getUserAccounts() {
        User currentUser = getCurrentUser();
        List<Account> accounts = accountRepository.findByUserIdAndActiveTrue(currentUser.getId());
        
        return accounts.stream()
                .map(this::convertToAccountResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public AccountResponseDTO getAccountById(Long accountId) {
        User currentUser = getCurrentUser();
        Account account = accountRepository.findByIdAndUserId(accountId, currentUser.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Account not found with id: " + accountId));

        return convertToAccountResponse(account);
    }

    @Transactional
    public AccountResponseDTO updateAccount(Long accountId, AccountRequestDTO accountRequest) {
        User currentUser = getCurrentUser();
        Account account = accountRepository.findByIdAndUserId(accountId, currentUser.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Account not found with id: " + accountId));

        account.setAccountName(accountRequest.getAccountName());
        account.setDescription(accountRequest.getDescription());
        account.setCreditLimit(accountRequest.getCreditLimit());
        account.setInterestRate(accountRequest.getInterestRate());

        Account updatedAccount = accountRepository.save(account);
        log.info("Account updated successfully with ID: {}", updatedAccount.getId());

        return convertToAccountResponse(updatedAccount);
    }

    @Transactional
    public void deleteAccount(Long accountId) {
        User currentUser = getCurrentUser();
        Account account = accountRepository.findByIdAndUserId(accountId, currentUser.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Account not found with id: " + accountId));

        if (account.getBalance().compareTo(java.math.BigDecimal.ZERO) != 0) {
            throw new CustomBusinessException("Cannot delete account with non-zero balance");
        }

        account.setActive(false);
        accountRepository.save(account);
        log.info("Account deactivated successfully with ID: {}", account.getId());
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private String generateAccountNumber() {
        StringBuilder accountNumber = new StringBuilder(accountNumberPrefix);
        
        for (int i = 0; i < 10; i++) {
            accountNumber.append(SECURE_RANDOM.nextInt(10));
        }
        
        // Ensure uniqueness
        while (accountRepository.existsByAccountNumber(accountNumber.toString())) {
            accountNumber = new StringBuilder(accountNumberPrefix);
            for (int i = 0; i < 10; i++) {
                accountNumber.append(SECURE_RANDOM.nextInt(10));
            }
        }
        
        return accountNumber.toString();
    }

    private AccountResponseDTO convertToAccountResponse(Account account) {
        AccountResponseDTO response = new AccountResponseDTO();
        response.setId(account.getId());
        response.setAccountNumber(account.getAccountNumber());
        response.setAccountType(account.getAccountType());
        response.setBalance(account.getBalance());
        response.setAccountName(account.getAccountName());
        response.setDescription(account.getDescription());
        response.setActive(account.getActive());
        response.setCreditLimit(account.getCreditLimit());
        response.setInterestRate(account.getInterestRate());
        response.setCreatedAt(account.getCreatedAt());
        response.setUpdatedAt(account.getUpdatedAt());
        
        return response;
    }
}