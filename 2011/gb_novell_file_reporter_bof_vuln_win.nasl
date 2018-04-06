###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_bof_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:novell:file_reporter";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.

  Impact Level: Application/System";
tag_affected = "Novell File Reporter (NFR) before 1.0.2";
tag_insight = "The flaw exists within 'NFRAgent.exe' module, which allows remote attackers
  to execute arbitrary code via unspecified XML data to port 3037.";
tag_solution = "Upgrade Novell File Reporter 1.0.2 or later,
  For updates refer to http://download.novell.com/Download?buildid=rCAgCcbPH9s~";
tag_summary = "This host is installed with Novell File Reporter and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801918");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0994");
  script_bugtraq_id(47144);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-116/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517321/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/FileReporter/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for  Novell File Reporter version less than 1.0.2
## Novell File Reporter(1.0.1) 1.0.117
if( version_is_less_equal( version:vers, test_version:"1.0.117" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );