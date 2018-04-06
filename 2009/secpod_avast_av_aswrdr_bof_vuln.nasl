###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avast_av_aswrdr_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# avast! 'aswRdr.sys' Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to cause a Denial of
  Service or potentially gain escalated privileges.
  Impact Level: System/Application";
tag_affected = "avast! Home and Professional version 4.8.1356 and prior on Windows.";
tag_insight = "The vulnerability is due to an error in 'aswRdr.sys' when processing
  IOCTLs. This can be exploited to corrupt kernel memory via a specially crafted
  0x80002024 IOCTL.";
tag_solution = "Upgrade to avast! Home and Professional version 4.8.1367 or later
  For updates refer to http://www.avast.com/eng/download.html";
tag_summary = "This host is installed with avast! AntiVirus and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900985");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4049");
  script_bugtraq_id(37031);
  script_name("avast! 'aswRdr.sys' Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37368/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/388054.php");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3266");
  script_xref(name : "URL" , value : "http://www.efblog.net/2009/11/avast-aswrdrsys-kernel-pool-corruption.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_require_keys("Avast!/AV/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

avastVer = get_kb_item("Avast!/AV/Win/Ver");
if(isnull(avastVer)){
  exit(0);
}

# Check for avast! version 4.8.1356 and prior
if(version_is_less_equal(version:avastVer, test_version:"4.8.1356.0"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!sysPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:sysPath +
                                                     "\drivers\aswRdr.sys");
  # Get the version of aswRdr.sys
  sysVer = GetVer(share:share, file:file);
  if((sysVer != NULL) && version_is_equal(version:sysVer,
                                          test_version:"4.8.1356.0")){
   security_message(0);
  }
}
