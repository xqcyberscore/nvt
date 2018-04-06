###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_strawberry_perl_dos_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Strawberry Perl Denial of Service Vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow attackers to cause denial of service
  (memory consumption) via specially-crafted hash key.
  Impact Level: Application";

tag_summary = "The host is installed with Strawberry Perl and is prone to denial
  of service vulnerability.";
tag_solution = "Upgrade to Strawberry Perl version 5.16.3 or 5.14.4 or later,
  For updates refer to http://strawberryperl.com";
tag_insight = "Flaw is due to an error when rehashing user-supplied input.";
tag_affected = "Strawberry Perl versions 5.8.2 before 5.14.4 and 5.15 before 5.16.3 on Windows";

if(description)
{
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_oid("1.3.6.1.4.1.25623.1.0.803371");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1667");
  script_bugtraq_id(58311);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-09 18:21:13 +0530 (Tue, 09 Apr 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Strawberry Perl Denial of Service Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52472");
  script_xref(name : "URL" , value : "http://perlnews.org/2013/03/rehashing-flaw");
  script_xref(name : "URL" , value : "http://perlnews.org/2013/03/perl-5-16-3-and-5-14-4-just-released");
  script_xref(name : "URL" , value : "http://www.nntp.perl.org/group/perl.perl5.porters/2013/03/msg199755.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
spVer = "";

## Get version from KB
spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer && spVer =~ "^5\.")
{
  if(version_in_range(version:spVer, test_version:"5.8.2", test_version2:"5.14.3")||
     version_in_range(version:spVer, test_version:"5.15", test_version2:"5.16.2"))
  {
    security_message(0);
    exit(0);
  }
}
