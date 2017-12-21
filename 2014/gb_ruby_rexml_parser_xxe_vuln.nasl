###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rexml_parser_xxe_vuln.nasl 8196 2017-12-20 12:13:37Z cfischer $
#
# Ruby 'REXML' Parser XML Entity Expansion (XEE) Vulnerability (Windows)
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

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805202");
  script_version("$Revision: 8196 $");
  script_cve_id("CVE-2014-8090");
  script_bugtraq_id(71230);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 13:13:37 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-12-01 18:02:14 +0530 (Mon, 01 Dec 2014)");
  script_name("Ruby 'REXML' Parser XML Entity Expansion (XEE) Vulnerability (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Ruby and is
  prone to XML entity expansion vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exists due to an error within the
  REXML module when parsing XML entities.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to cause a denial of service (crash) condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Ruby versions Ruby 1.9.x before 1.9.3-p551,
  2.0.x before 2.0.0-p598, and 2.1.x before 2.1.5 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Ruby 1.9.3-p551 or 2.0.0-p598 or
  2.1.5 later. For updates refer http://www.ruby-lang.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2014/11/13/rexml-dos-cve-2014-8090");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_mandatory_keys("Ruby/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
rubyVer = "";

## Get version from KB
if(!rubyVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(rubyVer)
{
  ## Check for version 1.9.x before 1.9.3-p551, 2.0.x before 2.0.0-p598
  if(version_in_range(version:rubyVer, test_version:"1.9.0.0", test_version2:"1.9.3.p550")||
     version_in_range(version:rubyVer, test_version:"2.0.0.0", test_version2:"2.0.0.p597"))
  {
    security_message(0);
  }
}

##Check for 2.1.x before 2.1.5.0
if(rubyVer =~ "^(2\.1\.)")
{
  if(version_is_less(version:rubyVer, test_version:"2.1.5.0"))
  {
    security_message(0);
    exit(0);
  }
}
