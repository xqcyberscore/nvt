###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_unspecified_vuln.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Acrobat Unspecified vulnerability
#
# Authors:
# Nikta MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:adobe:acrobat";

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  on the affected system via malicious files.

  Impact Level: Application/System";

tag_summary = "This host has Adobe Acrobat installed which is prone to unspecified
  vulnerability.";

tag_affected = "Adobe Acrobat version 9.x before 9.2 on Windows.";

tag_insight = "An unspecified error in Adobe Acrobat can be exploited to bypass intended
  file-extension restrictions via unknown vectors.";

tag_solution = "Upgrade to Adobe Acrobat version 9.2
  For updates refer to http://www.adobe.com/downloads/";

if(description)
{
  script_id(800959);
  script_version("$Revision: 8210 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3461");
  script_bugtraq_id(36638);
  script_name("Adobe Acrobat Unspecified vulnerability");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-15.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Check for Adobe Reader version 9.x prior to 9.2
if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );