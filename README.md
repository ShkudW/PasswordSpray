# PasswordSpray
This Tool was built as a reference to the excellent DomainPasswordSpray tool -> https://github.com/dafthack/DomainPasswordSpray
I love the logic in that code, but for example the tool didn’t work for me when I used it with a Kerberos ticket on my workstation.
And a few other small, annoying things that ended up requiring me to change things in the code every time.

So I wrote this code from scratch
Here are some things you should know about this tool:
1. The code discovers the PDC (Primary Domain Controller) to query the domain password policy.
2. The tool uses LDAP (simple LDAP binds) only.
3. You can run it from a non-joined workstation, as long as you have a valid ticket (LDAP/KRB-TGT) in your PowerShell session.
4. The tool skips accounts that are currently locked out and also skips accounts that are about to be locked (by reading their badPwdCount attribute).
5. Be careful running this in production environments.
6. Enjoy.
