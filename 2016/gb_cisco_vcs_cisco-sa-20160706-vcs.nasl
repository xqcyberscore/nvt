###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_cisco-sa-20160706-vcs.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Cisco TelePresence Video Communication Server (VCS) Authentication Bypass Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

tag_impact = "Successful exploitation will allow an unauthenticated, remote attacker to bypass authentication and access internal HTTP system resources.

Impact Lever: Application ";

tag_insight = "The flaw exists due to lack of proper input validation of a trusted certificate. ";

tag_affected = "Cisco TelePresence Video Communication Server (VCS) X8.1 through X8.7 and Expressway X8.1 through X8.6. ";

tag_summary = "This host is running Cisco TelePresence Video Communication Server and is prone to Authentication Bypass Vulnerability. "; 

tag_solution = "Updates are available.The advisory is available at the following link: 
http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160706-vcs" ;

tag_vuldetect = "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not. " ; 

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.107025");
 script_cve_id("CVE-2016-1444");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_version ("$Revision: 7573 $");
 script_name("Cisco TelePresence Video Communication Server (VCS) Authentication Bypass Vulnerability");
 script_xref(name:"URL", value: "http://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20160706-vcs.html");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2016-07-11 16:46:52 +0200 (Mon, 11 Jul 2016)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_vcs_detect.nasl","gb_cisco_vcs_ssh_detect.nasl");
 script_mandatory_keys("cisco_vcs/installed");
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);
 exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Get version
if(!version = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

if(version_in_range(version:version, test_version:"8.1", test_version2:"8.7.0"))
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     Apply updates from Vendor\n';
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
