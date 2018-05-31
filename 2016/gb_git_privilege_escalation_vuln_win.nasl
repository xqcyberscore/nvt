##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_git_privilege_escalation_vuln_win.nasl 10042 2018-05-31 12:56:04Z jschulte $
#
# Git Privilege Escalation Vulnerability - Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:git_for_windows_project:git_for_windows";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809816");
  script_version("$Revision: 10042 $");
  script_cve_id("CVE-2016-9274");
  script_bugtraq_id(94289);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 14:56:04 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2016-11-22 11:18:59 +0530 (Tue, 22 Nov 2016)");
  script_name("Git Privilege Escalation Vulnerability - Windows");

  script_tag(name: "summary" , value:"The host is installed with Git
  and is prone privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name: "insight" , value:"The flaw exists due to an untrusted search
  path vulnerability.");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow  local users to gain privileges via a Trojan horse
  git.exe file in the current working directory.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Git version prior to 2.0 on Windows");

  script_tag(name: "solution", value:"Upgrade to Git version 2.0 or later
  For updates refer to https://git-scm.com/download/win");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://github.com/git-for-windows/git/issues/944");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!git_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:git_ver, test_version:"2.0"))
{
  report = report_fixed_ver(installed_version:git_ver, fixed_version:"2.0");
  security_message(data:report);
  exit(0);
}

