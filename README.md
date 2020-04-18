# PAM authentication message
`pam-auth-msg` is a PAM module written in python  3 that allows the sending of 
notifications and one-time-pins (OTP) via SMS and mail whenever a user logs in 
through a PAM enabled service like SSH.

## installation
* copy `pam-auth-msg.py` to `/usr/local/bin/pam-auth-msg.py`
* copy `authmsg.conf` to `/etc/authmsg.conf` and configure the default values.
* add lines to the `/etc/pam.d/sshd` config file as shown in the example 
`pam_sshd` file
  * near the top:
    ```
    auth requisite pam_python.so /usr/local/bin/pam-auth-msg.py
    ```
  * towards the bottom:
    ```
    session optional pam_python.so /usr/local/bin/pam-auth-msg.py
    ```
* optionally copy `authmsg.conf` to any users home directory as 
  `~/.authmsg.conf` to overwrite default values

## dependencies
 * python3-pam
