DBManagerPlugin
===============
3proxy plugin for forwarding socks5/http-connect/etc connections based on provided in socks5
username field (with username format: appusr-proxyip-proxyport:apppasswd (usr-xxx.xxx.xxx.xxx-xxxxx:passwd))

Depends
=======
unixODBC - driver for mysql db

Setup
============
Install unixODBC
Setup unixODBC configuration(sample configuration files found in cfg directory)
Apply cfg/3proxy.patch before building the 3proxy+plugin
Setup 3proxy configuration(sample in cfg)
Launch 3proxy with the given configuration
