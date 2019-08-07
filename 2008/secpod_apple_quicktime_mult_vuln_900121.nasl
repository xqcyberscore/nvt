##############################################################################
# OpenVAS Vulnerability Test
# Description: Apple QuickTime Movie/PICT/QTVR Multiple Remote Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900121");
  script_version("2019-08-06T11:17:21+0000");
  script_tag(name:"last_modification", value:"2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_bugtraq_id(31086);
  script_cve_id("CVE-2008-3615", "CVE-2008-3635", "CVE-2008-3624", "CVE-2008-3625",
               "CVE-2008-3614", "CVE-2008-3626", "CVE-2008-3627", "CVE-2008-3628",
               "CVE-2008-3629");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Apple QuickTime Movie/PICT/QTVR Multiple Remote Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496163");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=744");

  script_tag(name:"summary", value:"This host has Apple QuickTime installed, which is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to,

  - an uninitialized memory access inn the Indeo v5 codec and lack of
  proper bounds checking within QuickTimeInternetExtras.qtx file.

  - improper handling of panorama atoms in QTVR movie files.

  - improper handling of maxTilt, minFieldOfView and maxFieldOfView
  parameters in panorama track PDAT atoms.

  - an uninitialized memory access in the third-party Indeo v5 codec.

  - an invalid pointer in handling of PICT images.

  - memory corruption in handling of STSZ atoms in movie files within
  CallComponentFunctionWithStorage() function.

  - multiple memory corruption in H.264 encoded movie files.

  - parsing of movie video files in QuickTimeH264.scalar and MP4 video
  files in QuickTimeH264.qtx.");

  script_tag(name:"affected", value:"Apple QuickTime versions prior to 7.5.5 on Windows (all).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 7.5.5.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain
  unauthorized access to execute arbitrary code and trigger a denial of service condition.");

  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(egrep(pattern:"^([0-6]\..*|7\.([0-4](\..*)?|5(\.[0-4])?))$",
         string:get_kb_item("QuickTime/Win/Ver"))){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
