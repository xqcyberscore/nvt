###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_audition_ses_mult_bof_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:adobe:audition";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary
code or cause a denial of service via crafted data in unspecified fields in
the TRKM chunk in an Audition Session file.

Impact Level: Application";

tag_affected = "Adobe Audition version 3.0.1 and earlier on Windows";

tag_insight = "The flaw is due to an error when handling '.SES' (session) format
file, which results in memory corruption, application crash or possibly
execute arbitrary code.";

tag_solution = "Upgrade to version CS5.5 or higher,
For updates refer to http://www.adobe.com/products/audition.html";

tag_summary = "The host is installed with Adobe Audition and is prone to multiple
buffer overflow vulnerabilities.";

if(description)
{
  script_id(902373);
  script_version("$Revision: 8210 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-0614", "CVE-2011-0615");
  script_bugtraq_id(47841, 47838);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17278/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-10.html");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5012.php");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/Adobe-Audition-malformed-SES-file");
  
  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Audition/Win/Installed");
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

## Check for Adobe Audition version <= 3.0.1
if( version_is_less_equal( version:vers, test_version:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"CS5.5", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );