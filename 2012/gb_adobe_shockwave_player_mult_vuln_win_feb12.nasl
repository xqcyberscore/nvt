###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_win_feb12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated By: Rajat Mishra <rajatm@secpod.com> on 2018-02-19
# - Updated to include Installation path in the report.
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:shockwave_player";

tag_impact = "Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.
  Impact Level: System/Application";
tag_affected = "Adobe Shockwave Player Versions 11.6.3.633 and prior on Windows.";
tag_insight = "The flaws are due to memory corruptions errors in Shockwave 3D Asset
  component when processing malformed file.";
tag_solution = "Upgrade to Adobe Shockwave Player version 11.6.4.634 or later,
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802398");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0757", "CVE-2012-0759", "CVE-2012-0760", "CVE-2012-0761",
                "CVE-2012-0762", "CVE-2012-0763", "CVE-2012-0764", "CVE-2012-0766",
                "CVE-2012-0758", "CVE-2012-0771");
  script_bugtraq_id(51999, 52006, 52000, 52001, 52002, 52003, 52004, 52005, 52007);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-17 12:55:43 +0530 (Fri, 17 Feb 2012)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47932/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026675");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-02.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variables Initialization
vers = "";

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];


## Check for Adobe Shockwave Player versions prior to 11.6.4.634
if(version_is_less(version:vers, test_version:"11.6.4.634"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.6.4.634", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);  
