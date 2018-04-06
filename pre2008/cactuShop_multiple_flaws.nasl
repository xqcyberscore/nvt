# OpenVAS Vulnerability Test
# $Id: cactuShop_multiple_flaws.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: CactuShop XSS and SQL injection flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host runs CactuShop, an e-commerce web application written in ASP.

The remote version of this software is vulnerable to cross-site scripting 
due to a lack of sanitization of user-supplied data in the script 
'popuplargeimage.asp'.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

This version may also be vulnerable to SQL injection attacks in 
the scripts 'mailorder.asp' and 'payonline.asp'. The user-supplied 
input parameter 'strItems' is not filtered before being used in 
an SQL query. Thus the query modification through malformed input 
is possible.

Successful exploitation of this vulnerability can enable an attacker
to execute commands in the system (via MS SQL the function xp_cmdshell).";

tag_solution = "Upgrade to the latest version of this software";

# Ref: Nick Gudov <cipher@s-quadra.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15461");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1881", "CVE-2004-1882");
  script_bugtraq_id(10019, 10020);
  script_xref(name:"OSVDB", value:4785);
  script_xref(name:"OSVDB", value:4786);
  script_xref(name:"OSVDB", value:4787);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  
  script_name("CactuShop XSS and SQL injection flaws");

 

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/popuplargeimage.asp?strImageTag=<script>foo</script> ", port:port);
r = http_keepalive_send_recv(port:port, data:buf);
if( r == NULL )exit(0);

if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
{
  security_message(port);
  exit(0);
}
