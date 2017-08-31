###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_dos_vuln_feb14_win.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Active Perl Denial of Service Vulnerability Feb 2014 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:perl:perl";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804315";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2010-4777");
  script_bugtraq_id(47006);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-17 10:12:58 +0530 (Mon, 17 Feb 2014)");
  script_name("Active Perl Denial of Service Vulnerability Feb 2014 (Windows)");

  tag_summary =
"The host is installed with Active Perl and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to improper handling of crafted input by
'Perl_reg_numbered_buff_fetch' function.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service.

Impact Level: Application";

  tag_affected =
"Active Perl versions 5.10.0, 5.12.0, 5.14.0 and other versions.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1029735");
  script_xref(name : "URL" , value : "http://news.debuntu.org/content/56643-cve-2010-4777-perl");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4777");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
perlVer = "";

## Get version
if(!perlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_equal(version:perlVer, test_version:"5.10.0")||
  version_is_equal(version:perlVer, test_version:"5.12.0")||
  version_is_equal(version:perlVer, test_version:"5.14.0"))
{
  security_message(0);
  exit(0);
}
