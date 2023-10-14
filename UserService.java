package com.SocialMedia.app.services;

import com.SocialMedia.app.DTO.RegistrationUserDTO;
import com.SocialMedia.app.DTO.RequestUserDTO;
import com.SocialMedia.app.DTO.ResponseUserDTO;
import com.SocialMedia.app.exceptions.RegistrationUserException;
import com.SocialMedia.app.models.Role;
import com.SocialMedia.app.models.User;
import com.SocialMedia.app.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository repository;
    private final RoleService roleService;
    private final PasswordEncoder encoder;


    public Iterable<User> findAllUser() {
        return repository.findAll();
    }

    public Optional<User> findUserByLogin(String login) {
        return repository.findByLogin(login);
    }

    public User saveUser(RegistrationUserDTO user) throws RegistrationUserException {
        if (!user.getPassword().equals(user.getConfirmPassword())) {
            throw new RegistrationUserException("Password mismatch " + user.getPassword() + " " + user.getConfirmPassword());
        }
        if (findUserByLogin(user.getLogin()).isPresent()) {
            throw new RegistrationUserException("User with this login exists");
        }
        for (Role r : user.getRoles()) {
            if (!roleService.findByRole(r.getRole()).isPresent()) {
                throw new RegistrationUserException("No such role exists -> " + r.getRole());
            }
        }
        User savedUser = new User(user.getLogin(), encoder.encode(user.getPassword()), user.getRoles());
        repository.save(savedUser);
        return savedUser;
    }

    public User deleteUser(RequestUserDTO user) {
        Optional<User> resUser = repository.findByLogin(user.getLogin());
        if (resUser.isPresent()) {
            repository.delete(resUser.get());
            return resUser.get();
        }
        return null;
    }

    public User updateUser(User user) throws RegistrationUserException {
        var delUser = deleteUser(convertUserToRequestUserDTO(user));
        if (delUser != null) {
            saveUser(new RegistrationUserDTO(delUser.getLogin(), delUser.getPassword(), delUser.getPassword(), delUser.getRoles()));
        }
        return delUser;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findUserByLogin(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(
                user.getLogin(),
                user.getPassword(),
                user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getRole())).collect(Collectors.toList())
        );
    }

    public List<ResponseUserDTO> convertUserToResponseUserDTO(Iterable<User> users) {
        List<ResponseUserDTO> response = new ArrayList<>();
        for (User u : users) {
            response.add(convertUserToResponseUserDTO(u));
        }
        return response;
    }

    public ResponseUserDTO convertUserToResponseUserDTO(User user) {
        return new ResponseUserDTO(user.getLogin(), user.getRoles());
    }

    public RequestUserDTO convertUserToRequestUserDTO(User user) {
        return new RequestUserDTO(user.getLogin(), user.getPassword());
    }
}
