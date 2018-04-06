###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_utf8_regex_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Perl UTF-8 Regular Expression Processing DoS Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Apply the patch.
  http://perl5.git.perl.org/perl.git/commit/0abd0d78a73da1c4d13b1c700526b7e5d03b32d4

  *****
  NOTE: Ignore this warning if the above mentioned patch is already applied.
  *****";

tag_impact = "Attackers can exploit this issue to crash an affected application via
  specially crafted UTF-8 data leading to Denial of Service.
  Impact Level: Application";
tag_affected = "Perl version 5.10.1 on Windows.";
tag_insight = "An error occurs in Perl while matching an utf-8 character with large or
  invalid codepoint with a particular regular expression.";
tag_summary = "The host is installed with Perl and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800967");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3626");
  script_bugtraq_id(36812);
  script_name("Perl UTF-8 Regular Expression Processing DoS Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53939");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/10/23/8");
  script_xref(name : "URL" , value : "https://issues.apache.org/SpamAssassin/show_bug.cgi?id=6225");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

apVer = get_kb_item("ActivePerl/Ver");
if(!isnull(apVer) && version_is_equal(version:apVer, test_version:"5.10.1"))
{
  security_message(0);
  exit(0);
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(!isnull(spVer) && version_is_equal(version:spVer, test_version:"5.10.1")){
  security_message(0);
}
