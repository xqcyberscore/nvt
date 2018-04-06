###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_mult_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Air and Flash Player Multiple Vulnerabilities (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "Adobe Air versions prior to 2.7.1
  Adobe Flash Player versions prior to 10.3.183.5";
tag_insight = "Multiple flaws are caused by memory corruptions, cross-site information
  disclosure, buffer overflow and integer overflow errors.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.5 and Adobe Air version
  2.7.1 or later.
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Air and/or Flash Player and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902712");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2137",
                "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2138",
                "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414",
                "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417",
                "CVE-2011-2425", "CVE-2011-2424");
  script_bugtraq_id(49073, 49074, 49075, 49082, 49079, 49080, 49086, 49083,
                    49076, 49077, 49081, 49084, 49085);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Air and Flash Player Multiple Vulnerabilities (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get Adobe Flash Player version from KB
flashVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(flashVer)
{
  ## Check for Adobe flash player versions < 10.3.183.5
  if(version_is_less(version:flashVer, test_version:"10.3.183.5"))
  {
    security_message(0);
    exit(0);
  }
}

## Get Adobe Air version from KB
airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
   ## Check for Adobe air versions < 2.7.1
  if(version_is_less(version:airVer, test_version:"2.7.1")){
    security_message(0);
  }
}
