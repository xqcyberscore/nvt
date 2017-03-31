###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freewebshop_55567.nasl 3911 2016-08-30 13:08:37Z mime $
#
# FreeWebshop Multiple SQL Injection and Cross Site Scripting Vulnerabilities
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

tag_summary = "FreeWebshop is prone to multiple SQL-injection and cross-site
scripting vulnerabilities because it fails to sufficiently sanitize
user-supplied input.

Exploiting these vulnerabilities could allow an attacker to steal
cookie-based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.

FreeWebshop 2.2.9 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103570";
CPE = "cpe:/a:freewebshop:freewebshop";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55567);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 3911 $");

 script_name("FreeWebshop Multiple SQL Injection and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55567");
 script_xref(name : "URL" , value : "http://www.freewebshop.org");

 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2012-09-18 13:18:37 +0200 (Tue, 18 Sep 2012)");
 script_summary("Determine if FreeWebshop is vulnerable.");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("FreeWebShop_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("FreeWebshop/installed");
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
url = dir + '/index.php?page=browse&searchfor=<script>alert(/openvas-xss-test/)</script>';

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
