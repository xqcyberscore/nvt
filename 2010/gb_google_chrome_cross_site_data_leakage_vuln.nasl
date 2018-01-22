###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_cross_site_data_leakage_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Google Chrome Cross Site Data Leakage Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the remote web servers to
identify specific persons and their product searches via 'HTTP' request login.

Impact Level: Application";

tag_affected = "Google Chrome version 4.0.249.78 and proir on Windows.";

tag_insight = "The flaw is due to an error in handling background 'HTTP' requests.
It uses cookies in possibly unexpected manner when the 'Invisible Hand extension'
is enabled.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Google Chrome Web Browser and is
prone to cross site data leakage vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801329");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1851");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Google Chrome Cross Site Data Leakage Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.cnet.com/8301-31361_1-20004265-254.html");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/01/stable-channel-update_25.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

# Check for google chrome Version less than or equal 4.0.249.78
if(version_is_less_equal(version:gcVer, test_version:"4.0.249.78")){
  security_message(0);
}
