# OpenVAS Vulnerability Test
# $Id: visnetic_mailserver_flaws.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: VisNetic / Merak Mail Server multiple flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote webmail server is affected by multiple vulnerabilities 
which may allow an attacker to execute arbitrary commands on the remote
host.

Description:

The remote host is running VisNetic / Merak Mail Server, a
multi-featured mail server for Windows. 

The webmail and webadmin services included in the remote version of
this software are prone to multiple flaws.  An attacker could send
specially-crafted URLs to execute arbitrary scripts, perhaps taken
from third-party hosts, or to disclose the content of files on the
remote system.";

tag_solution = "Upgrade to Merak Mail Server 8.3.5.r / VisNetic Mail Server version
8.3.5 or later.";

# Ref: Tan Chew Keong, Secunia Research

if(description)
{
 script_id(20346);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2005-4556", "CVE-2005-4557", "CVE-2005-4558", "CVE-2005-4559");
 script_bugtraq_id(16069);
  
 name = "VisNetic / Merak Mail Server multiple flaws";
 script_name(name);
 
 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports(32000, "Services/www");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2005-62/advisory/");
 script_xref(name : "URL" , value : "http://www.deerfield.com/download/visnetic-mailserver/");
 exit(0);
}

#
# da code
#

include("http_func.inc");
include("http_keepalive.inc");

if ( !get_kb_item("Settings/disable_cgi_scanning") )
 port = get_http_port(default:32000);
else
 port = 32000;

if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {
  req = http_get(item:string(dir, "/accounts/inc/include.php?language=0&lang_settings[0][1]=http://xxxxxxxxxxxxxxx/openvas/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("http://xxxxxxxxxxxxxxx/openvas/alang.html" >< r)
  {
   security_message(port);
   exit(0);
  }
}
