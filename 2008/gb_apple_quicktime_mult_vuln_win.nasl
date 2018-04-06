###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Apple QuickTime Multiple Arbitrary Code Execution Vulnerabilities (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful exploitation allow attackers to execute arbitrary
  code or unexpected application termination.
  Impact Level : Application";

tag_solution = "Upgrade to Apple QuickTime version 7.5 or later,
  http://www.apple.com/quicktime/download/";


tag_summary = "The host is installed with Apple QuickTime which is prone to
  Multiple Arbitrary Code Execution Vulnerabilities.";

tag_affected = "Apple QuickTime before 7.5 on Windows (Any).";
tag_insight = "The flaws are due to
  - boundary error when parsing packed scanlines from a PixData
    structure in a PICT file which can be exploited via specially crafted
    PICT file.
  - memory corruption issue in AAC-encoded media content can be
    exploited via a specially crafted media file.
  - error in the handling of PICT files or Indeo video codec content that
    can be exploited via a specially crafted PICT file or movie file with
    Indeo video codec content respectively.
  - error in the handling of file URLs that can be exploited by making user
    to play maliciously crafted QuickTime content.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800102");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1581","CVE-2008-1582","CVE-2008-1583",
                "CVE-2008-1584","CVE-2008-1585");
  script_bugtraq_id(29619);
  script_xref(name:"CB-A", value:"08-0094");
  script_name("Apple QuickTime Multiple Arbitrary Code Execution Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1991");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29293");
  script_xref(name : "URL" , value : "http://www.nruns.com/security_advisory_quicktime_arbitrary_code_execution.php");
  exit(0);
}


# Grep for QuickTime version <= 7.5
if(egrep(pattern:"^([0-6]\..*|7\.([0-4](\..*)?))$",
         string:get_kb_item("QuickTime/Win/Ver"))){
  security_message(0);
}
