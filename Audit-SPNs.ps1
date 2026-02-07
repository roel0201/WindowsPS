# Find all accounts with SPNs (Potential Kerberoasting targets)
setspn -T domain.local -Q */* | Out-File $HOME\Desktop\spn_audit.txt

# Check for accounts with "Do not require Kerberos preauthentication"
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' -Properties DoesNotRequirePreAuth
