###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_mult_vuln01_sep15.nasl 7754 2017-11-14 11:15:34Z asteins $
#
# pfSense Multiple Vulnerabilities -01 Sep15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:pfsense:pfsense";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805970");
  script_version("$Revision: 7754 $");
  script_cve_id("CVE-2014-4687", "CVE-2014-4688", "CVE-2014-4689", "CVE-2014-4690",
                "CVE-2014-4691", "CVE-2014-4692");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-14 12:15:34 +0100 (Tue, 14 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-09-04 14:53:21 +0530 (Fri, 04 Sep 2015)");
  script_name("pfSense Multiple Vulnerabilities -01 Sep15");

  script_tag(name:"summary", value:"This host is running pfSense and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists as,
  - Input passed via 'the starttime0' parameter to firewall_schedule.php,
  the 'rssfeed' parameter to rss.widget.php, the 'servicestatusfilter' parameter
  to services_status.widget.php, the 'txtRecallBuffer' parameter to exec.php and the
  HTTP Referer header to log.widget.php is not proper validated and encoded.
  - Input passed via POST request on diag_dns.php script during the 'Create Alias'
  action is not properly validated or sanitized.
  - Input passed via 'update e-mail' function on the diag_smart.php page is not
  properly validated or sanitized.
  - The database value passed to status_rrd_graph_img.php script is not properly
  validated or sanitized.
  - An error in pkg_edit.php which allows including XML files.
  - Errors in pkg_mgr_install.php and system_firmware_restorefullbackup.php scripts.
  - The session ID is not properly reset when initializing a new login session.
  - The session cookie set at login does not have the HttpOnly flag set when the
  firewall's GUI is configured to use HTTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack users session, gain access to sensitive files, execute
  arbitrary HTML and script code in a user's browser session in the context of
  an affected site and get elevated privileges, read arbitrary files, execute
  commands, or other impacts.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"pfSense before version 2.1.4");

  script_tag(name:"solution", value:"Upgrade to version 2.1.4 or later. For update
  refer to https://www.pfsense.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name : "URL" , value : "https://pfsense.org/security/advisories/pfSense-SA-14_09.webgui.asc");
  script_xref(name : "URL" , value : "https://pfsense.org/security/advisories/pfSense-SA-14_10.webgui.asc");
  script_xref(name : "URL" , value : "https://pfsense.org/security/advisories/pfSense-SA-14_11.webgui.asc");
  script_xref(name : "URL" , value : "https://pfsense.org/security/advisories/pfSense-SA-14_12.webgui.asc");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_pfsense_detect.nasl");
  script_mandatory_keys("pfsense/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
pfVer = "";

if(!pfVer = get_app_version(cpe:CPE, nofork:TRUE)) exit(0);

##Check version is < 2.1.4
if(version_is_less(version:pfVer, test_version:"2.1.4" ) )
{
  report = 'Installed version: ' + pfVer + '\n' +
           'Fixed version:     2.1.4';
  security_message( port:0, data:report);
  exit(0);
}
exit(99);
