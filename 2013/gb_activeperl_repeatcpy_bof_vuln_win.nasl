###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_repeatcpy_bof_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Active Perl 'Perl_repeatcpy()' Function Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to cause a denial of service
  (memory consumption and crash) or possibly execute arbitrary code via the
  'x' string repeat operator.
  Impact Level: System/Application";

tag_affected = "Active Perl 5.12.x before 5.12.5, 5.14.x before 5.14.3 and
  5.15.x before 15.15.5 on Windows";
tag_insight = "The Perl_repeatcpy() function in util.c fails to properly sanitize user
  supplied input while handling the string repeat operator.";
tag_solution = "Upgrade to Active Perl 5.12.5, 5.14.3, 15.15.5 or later,
  For updates refer to http://www.perl.org/get.html";
tag_summary = "The host is installed with Active Perl and is prone to heap based
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803338");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-5195");
  script_bugtraq_id(56287);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-23 19:28:09 +0530 (Wed, 23 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Active Perl 'Perl_repeatcpy()' Function Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51457");
  script_xref(name : "URL" , value : "http://www.nntp.perl.org/group/perl.perl5.porters/2012/10/msg193886.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
apVer = "";

## Get version from KB
apVer = get_kb_item("ActivePerl/Ver");
if(apVer && apVer =~ "^(5\.(12|14|15))")
{
  if(version_in_range(version:apVer, test_version:"5.12.0", test_version2:"5.12.4") ||
     version_in_range(version:apVer, test_version:"5.14.0", test_version2:"5.14.2") ||
     version_in_range(version:apVer, test_version:"5.15.0", test_version2:"5.15.4"))
  {
    security_message(0);
    exit(0);
  }
}
