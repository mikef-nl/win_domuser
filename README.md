# win_domuser
Ansible Windows Domain User Module

Example:
```
---
- hosts: windows
  tasks:
  - name: Domain User
    win_domuser:
      name: bob
      upn: bob@test.local
      password: P@ssw01rd!
      state: present
      ou: OU=Testing,DC=test,DC=local
      account_enabled: true
      fullname: bob jones
      description: Normal user
      password_expired: no
      user_cannot_change_password: no
      password_never_expires: yes
      groups: Domain Admins
      groups_action: add
