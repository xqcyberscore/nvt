###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_unspecified_vuln_macosx.nasl 11082 2018-08-22 15:05:47Z mmartin $
#
# Adobe Acrobat Multiple Unspecified Vulnerabilities - Mac OS X
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803804");
  script_version("$Revision: 11082 $");
  script_cve_id("CVE-2012-4363");
  script_bugtraq_id(55055);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-08-22 17:05:47 +0200 (Wed, 22 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-08-24 16:05:37 +0530 (Fri, 24 Aug 2012)");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50290");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application.
  Impact Level: System/Application");
  script_tag(name:"affected", value:"Adobe Acrobat versions 9.x to 9.5.2 and 10.x to 10.1.4 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to an unspecified errors.");
  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat 9.5.3, 10.1.5 or later,
  For updates refer to http://www.adobe.com");
  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat and is prone to
  multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Function to check the versions of abode acrobat
function version_check(ver)
{
  if(version_is_less(version:ver, test_version:"9.5.3") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");
if(acrobatVer){
  version_check(ver:acrobatVer);
}
