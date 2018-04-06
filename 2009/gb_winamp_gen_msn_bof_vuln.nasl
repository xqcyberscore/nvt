###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_gen_msn_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Winamp gen_msn.dll Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Attackers may leverage this issue by executing arbitrary code in the context
  of an affected application via specially crafted .pls files, and can cause
  buffer ovreflow.
  Impact Level: Application";
tag_affected = "Winamp version 5.541 and prior on Windows.";
tag_insight = "Boundary error exists in the player while processing overly long Winamp
  playlist entries in gen_msn.dll";
tag_solution = "Upgrade to Winamp version 5.572 or later
  For updates refer to http://www.winamp.com/plugins";
tag_summary = "This host has Winamp Player with gen_msn Plugin installed and
  is prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800531");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-12 08:39:03 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0833");
  script_bugtraq_id(33159);
  script_name("Winamp gen_msn.dll Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33425");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7696");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

# Check for version 5.541 (5.5.4.2165) and prior
if(version_is_less_equal(version:winampVer, test_version:"5.5.4.2165"))
{
  winampPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows" +
                                   "\CurrentVersion\App Paths\winamp.exe",
                               item:"Path");
  if(!winampPath){
    exit(0);
  }

  winampPath =  winampPath + "\Plugins\gen_msn.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winampPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winampPath);
  dllSize = get_file_size(share:share, file:file);

  if(dllSize != NULL && dllSize <= 45056){
    security_message(0);
  }
}
