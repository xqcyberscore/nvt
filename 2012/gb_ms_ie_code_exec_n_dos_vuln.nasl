###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_code_exec_n_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Internet Explorer Code Execution and DoS Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
code or cause denial of service.

Impact Level: System/Application";

tag_affected = "Microsoft Internet Explorer versions 6 through 9 and 10 Consumer Preview";

tag_insight = "The flaws are due to memory corruptions, and buffer overflow errors.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Microsoft Internet Explorer and is
prone to arbitrary code execution and denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802708");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1545");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-15 11:06:57 +0530 (Thu, 15 Mar 2012)");
  script_name("Microsoft Internet Explorer Code Execution and DoS Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.zdnet.com/blog/security/pwn2own-2012-ie-9-hacked-with-two-0day-vulnerabilities/10621");
  script_xref(name : "URL" , value : "http://arstechnica.com/business/news/2012/03/ie-9-on-latest-windows-gets-stomped-at-hacker-contest.ars");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
if(!ieVer){
  exit(0);
}

# Check for MS IE version 6.x, 7.x, 8.x and 9.x
if(version_is_equal(version:ieVer, test_version:"10.0.8250.0") ||
   version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.3790.3959") ||
   version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6001.16659") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702") ||
   version_in_range(version:ieVer, test_version:"9.0", test_version2:"9.0.8112.16421")){
  security_message(0);
}
