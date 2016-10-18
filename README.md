# Ubuntu Server Configurator Installer
Ubuntu Server Configurator Installer is a web server setup tool for ubuntu linux server, you can automate web server installation without touching the configuration files. There are 3 type of web server you can choose to install Apache2, Nginx, or Lighttpd.
This tool will help you installing a common web server for a website including FTP server, Database server, and PHP.
This setup tool will help those PHP programmers who need a development environment / website environment who don't want to take their time learning how to setup their OSes. On windows there is a XAMPP or WAMP, but in Linux you have to do it manually by hand to setup PHP environment.

# Installation
Before you can run this web server setup utility, please make sure you have a working internet connection, and also you have at least Ubuntu 9.04 (Jaunty Jackalope) installed on your system.
Download the package and log into your linux box and follow these following :

- Uncompress package
   unzip master.zip
- Change permission of setup file
   chmod 755 setup.sh
- Run the setup file
   ./setup.sh

# Uninstallation
You can uninstall all your installed package by using
- ./setup.sh --uninstall
