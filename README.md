# WebSHELL SSH Like PuTTY on Web
Make your SSH server accessible from the web browser.


It's a web ssh proxy. If deployed on certain server it can transform it to web ssh client. It is for remote ssh connections, not for the connection to the same server where it's deployed. See [Shellinabox](https://code.google.com/archive/p/shellinabox/) if you want to have just web ssh server on the same server you want connect to.

It is distributed in the form of Docker container which includes Shellinabox and python wrapper script and enables remote connections to arbitrary servers. It's based on the original [Shellinabox](https://code.google.com/archive/p/shellinabox/) and the [idea](https://blog.bartlweb.net/2013/10/ssh-web-gateway-mit-dem-opensource-tool-shellinabox/) of ssh client invocation.



# Usage

```bash
docker run -d --privileged --security-opt seccomp=unconfined --restart unless-stopped --name webshell -p 8018:8018 rickicode/webshell-ssh:latest
```

Navigate to http://hostname.com:8018/ to specify server ip, port and login interactively or 
- http://hostname.com:8018/?serverip
- http://hostname.com:8018/?serverip/port
- http://hostname.com:8018/?serverip/port/root
- http://hostname.com:8018/?serverip/port/root/encoded_base64_private_key

to use URL-based and default values

## Parameters

1. **SSH_PORT** - default port to use (if not specified - 22)
2. **USERNAME** - default login to use (if not specified - root)
3. **DEFAULT_IP** - default ip to use (if not specified, both ipv4 and ipv6 are ok)
5. **INACTIVITY_INTERVAL** - amount of seconds of noIO between remote server and browser after which the monitor script must terminate the connection (default 120)


## Notes

If you want to use a private key, you need to encode it in base64 and pass it as a parameter to the URL.


## Author

rickicode @ [NETQ.ME](https://netq.me/)

Forked from [Webshell](https://github.com/bwsw/webshell)
