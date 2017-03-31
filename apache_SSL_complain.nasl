# OpenVAS Vulnerability Test
# $Id: apache_SSL_complain.nasl 4683 2016-12-06 08:45:07Z cfi $
# Description: Detect Apache HTTPS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15588");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 4683 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:45:07 +0100 (Tue, 06 Dec 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Detect Apache HTTPS");
 script_summary("Web server complains that we are talking plain HTTP on HTTPS port");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 script_family( "Service detection");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 443);

 script_tag(name : "solution" , value : "Enable SSL tests in the 'Services' preference setting, or increase the 
 timeouts if this option is already set and the plugin missed 
 this port.");
 script_tag(name : "summary" , value : "An SSL detection issue might impede the OpenVAS Scan.

 Description :

 OpenVAS has discovered that it is talking in plain HTTP on a SSL port.

 OpenVAS has corrected this issue by enabled HTTPS on this port only. However 
 if other SSL ports are used on the remote host, they might be skipped.");

 script_tag(name:"qod_type", value:"remote_banner");

 exit(0);
}

# 

include("misc_func.inc");

banners = get_kb_list("FindService/tcp/*/get_http");
if (COMMAND_LINE)
{
  soc = http_open_socket(443);
  if (! soc) exit(0);
  req = string('GET / HTTP/1.0\r\n', 'Host: ', get_host_name(), '\r\n\r\n');
  send(socket: soc, data: req);
  banner = recv(socket: soc, length: 65535);
  http_close_socket(soc);
  if (! banner) exit(0);
  banners = make_array(443, banner);  
}
if ( isnull(banners) ) exit(0);

foreach p (keys(banners))
{
# If there are several values, get_kb_item will fork and that's bad.
# However, this only happens when the KB is saved?
  b = banners[p];
  port = ereg_replace(string: p, pattern: ".*/([0-9]+)/.*", replace: "\1");
  port = int(port);
  if (port)
    if (# Apache
        b =~ "<!DOCTYPE HTML .*You're speaking plain HTTP to an SSL-enabled server" ||
        # Webmin
        "Bad Request" >< b && "<pre>This web server is running in SSL mode" >< b)
  {
    log_message(port);
    if (COMMAND_LINE) display("\n **** SSL server detected on ", get_host_name(), ":", port, " ****\n\n");
    if (service_is_unknown(port: port)) 
      register_service(port: port, proto: "www");
    for (t = ENCAPS_SSLv2; t <= ENCAPS_TLSv12; t ++)
    {
      s = open_sock_tcp(port, transport: t);
      if (s)
      {
        req = string('GET / HTTP/1.0\r\n', 'Host: ', get_host_name(), '\r\n\r\n');
        send(socket: s, data: req);
        b = recv(socket: s, length: 4096);
        close(s);
        k = get_port_transport( port );
        replace_kb_item(name: k, value: t);
        if (b)
        {
          replace_kb_item(name: "FindService/tcp/"+port+"/get_http", value: b);
          replace_kb_item(name: "www/banner/"+port, value: b);
        }
        break;
      }
    }
  }
}

