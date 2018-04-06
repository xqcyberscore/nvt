# OpenVAS Vulnerability Test
# $Id: remote-Leap_CMS_multi.nasl 9350 2018-04-06 07:03:33Z cfischer $
# Description: This script multiple remote vulnerabilities on the Leap CMS
#
# remote-Leap_CMS_multi.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote Leap CMS is affected to multiple remote vulnerabilities. 
Leap is a single file, template independent, PHP and MySQL Content Management System.";

tag_solution = "for the sql injection vulnerability, set your php configuration to magic_quotes_gpc = off,
for other vulnerabilities, it's recommanded to download the latest stable version";


if(description)
{
script_oid("1.3.6.1.4.1.25623.1.0.101026");
script_version("$Revision: 9350 $");
script_cve_id("CVE-2009-1613", "CVE-2009-1614", "CVE-2009-1615");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
script_tag(name:"creation_date", value:"2009-04-30 23:55:19 +0200 (Thu, 30 Apr 2009)");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
name = "Leap CMS Multiple remote vulnerabilities";
script_name(name);
 
script_tag(name:"qod_type", value:"remote_banner"); 

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl", "remote-detect-Leap_CMS.nasl");
script_require_ports("Services/www", 80, 8080);
script_mandatory_keys("LeapCMS/installed");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

exit(0);

}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("LeapCMS/port");
version = get_kb_item("LeapCMS/version");
report = '';

if(!get_kb_item("LeapCMS/installed") || !port || !version)
	exit(0);
else {
	if(revcomp(a:version, b:"0.1.4") <= 0)
		report += "The current version " + version + " of LeapCMS is affected to multiple remote vulnerabilities";
}

if(report)
	security_message(port:port, data:report);
