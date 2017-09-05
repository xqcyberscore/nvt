###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_mult_bof_vuln_win.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# OpenSC Smart Card Serial Number Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901175");
  script_version("$Revision: 7052 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4523");
  script_bugtraq_id(45435);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OpenSC Smart Card Serial Number Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_mandatory_keys("OpenSC/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42658");
  script_xref(name:"URL", value:"https://www.opensc-project.org/opensc/changeset/4913");
  script_xref(name:"URL", value:"http://labs.mwrinfosecurity.com/files/Advisories/mwri_opensc-get-serial-buffer-overflow_2010-12-13.pdf");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause denial
  of service conditions.

  Impact Level: Application");
  script_tag(name:"affected", value:"OpenSC version 0.11.13 and prior.");
  script_tag(name:"insight", value:"The flaws are due to boundary errors in the 'acos_get_serialnr()',
  'acos5_get_serialnr()', and 'starcos_get_serialnr()' functions when reading
  out the serial number of smart cards.");
  script_tag(name:"summary", value:"This host is installed with OpenSC and is prone to multiple buffer
  overflow vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to OpenSC 0.12.0 or later.
  For updates refer to http://www.opensc-project.org/opensc");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

## Get version from KB
if(!oscVer = get_kb_item("OpenSC/Win/Ver")) exit(0);

## Check for OpenSC version 0.11.13 and prior
if(version_is_less_equal(version:oscVer, test_version:"0.11.13")) {
  report = report_fixed_ver(installed_version:oscVer, fixed_version:"0.12.0");
  security_message(data:report);
  exit(0);
}

exit(99);