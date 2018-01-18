###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_av_dos_vuln_mar10_win.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Aast! Antivirus 'aavmker4.sys' Denial Of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the local attackers to cause a Denial of
  Service or gain escalated privileges on the victim's system.
  Impact Level: System/Application";
tag_affected = "avast! Home and Professional version 4.8 to 4.8.1368.0 and
  avast! Home and Professional version 5.0 before 5.0.418.0 on Windows";
tag_insight = "The flaw is due to an error in the 'aavmker4.sys' kernel driver when
  processing certain IOCTLs. This can be exploited to corrupt kernel memory
  via a specially crafted 0xb2d60030 IOCTL.";
tag_solution = "Upgrade to avast! version  5.0.418  or later
  For updates refer to http://www.avast.com/eng/download.html";
tag_summary = "This host is installed with avast! AntiVirus and is prone to Denial
  Of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800479");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0705");
  script_bugtraq_id(38363);
  script_name("Aast! Antivirus 'aavmker4.sys' Denial Of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38689");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38677");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0449");
  script_xref(name : "URL" , value : "http://www.trapkit.de/advisories/TKADV2010-003.txt");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023644.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509710/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_require_keys("Avast!/AV/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

avastVer = get_kb_item("Avast!/AV/Win/Ver");
if(isnull(avastVer)){
  exit(0);
}

# Check for avast! version 4.8 to 4.8.1368.0 and 5.0 t0 5.0.417
if(version_in_range(version:avastVer, test_version:"5.0", test_version2:"5.0.417") ||
   version_in_range(version:avastVer, test_version:"4.8", test_version2:"4.8.1368.0"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!sysPath){
      exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:sysPath +
                                                     "\drivers\aavmker4.sys");
  # Get the version of aavmker4.sys
  sysVer = GetVer(share:share, file:file);
  if(!isnull(sysVer)) 
  {
    if(version_is_less(version:sysVer, test_version:"5.0.418.0")){
      security_message(0);
    }
  }
}
