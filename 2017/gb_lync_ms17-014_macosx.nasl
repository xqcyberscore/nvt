###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lync_ms17-014_macosx.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Microsoft Lync Certificate Validation Vulnerability-4013241 (MAC OS X)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:lync";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810817");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2017-0129");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-03-20 12:56:16 +0530 (Mon, 20 Mar 2017)");
  script_name("Microsoft Lync Certificate Validation Vulnerability-4013241 (MAC OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when the Lync client fails
  to properly validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to tamper the trusted communications between the server and target client.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Lync version 2011 for MAC OS X");

  script_tag(name:"solution", value:"Upgrade Microsoft Lync version 14.4.3.170308 or later,
  For updates refer to https://support.microsoft.com/en-us/help/4012487");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/4012487");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS17-014");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_lync_detect_macosx.nasl");
  script_require_keys("Microsoft/Lync/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variables Initialization
lyncVer = "";

## Get version
if(!lyncVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Check for lync 2011
if(lyncVer =~ "(^14\.)");
{
  # Check for vulnerable version
  if(version_is_less(version:lyncVer, test_version:"14.4.3.170308"))
  {
    report = report_fixed_ver(installed_version:lyncVer, fixed_version:"14.4.3.170308");
    security_message(data:report);
    exit(0);
  }
}
