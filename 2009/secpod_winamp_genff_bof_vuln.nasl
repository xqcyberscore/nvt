###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_genff_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Winamp gen_ff.dll Buffer Overflow Vulnerability
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

tag_impact = "Attackers may leverage this issue by executing arbitrary codes in the
  context of the affected application via specially crafted .maki files
  and can cause denial of service.
  Impact Level: System/Application";
tag_affected = "Winamp version 5.55 and prior on Windows.";
tag_insight = "The vulnerability exists in the gen_ff.dll file which is prone to integer
  overflow due to an incorrect type cast error while processing malicious
  .maki file.";
tag_solution = "Upgrade to the version 5.552
  http://www.winamp.com/player";
tag_summary = "This host is installed with Winamp and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900552");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1831");
  script_bugtraq_id(35052);
  script_name("Winamp gen_ff.dll Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://vrt-sourcefire.blogspot.com/2009/05/winamp-maki-parsing-vulnerability.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_require_ports(139, 445);
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

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

# Check for version 5.55 => 5.5.5.2405 and prior
if(version_is_less_equal(version:winampVer, test_version:"5.5.5.2405"))
{
  winPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\winamp.exe", item:"Path");
  if(!winPath){
    exit(0);
  }

  winPath =  winPath + "\Plugins\gen_ff.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winPath);
  dllSize = get_file_size(share:share, file:file);
  if(dllSize){
    security_message(0);
  }
}
