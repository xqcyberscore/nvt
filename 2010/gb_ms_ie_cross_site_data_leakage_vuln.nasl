###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_cross_site_data_leakage_vuln.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# Microsoft Internet Explorer Cross Site Data Leakage Vulnerability
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

tag_impact = "Successful exploitation will allow the remote web servers to
identify specific  persons and their product searches via 'HTTP' request login.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 8 and proir.";

tag_insight = "The flaw is due to an error in handling background 'HTTP'
requests. It uses cookies in possibly unexpected manner when the
'Invisible Hand extension' is enabled.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft Internet Explorer web
browser and is prone to cross site data leakage vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801330");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1852");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft Internet Explorer Cross Site Data Leakage Vulnerability");
  script_xref(name : "URL" , value : "http://www.cnet.com/8301-31361_1-20004265-254.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/windows/Internet-explorer/default.aspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(isnull(ieVer)){
  exit(0);
}

# Check for google chrome Version less than or equal 8
if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18702")){
  security_message(0);
}
