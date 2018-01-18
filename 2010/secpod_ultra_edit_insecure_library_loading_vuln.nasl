###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ultra_edit_insecure_library_loading_vuln.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# UltraEdit Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.org
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code.

Impact Level: Application.";

tag_affected = "UltraEdit version 16.20.0.1009 and prior.";

tag_insight = "The flaw exists due to the application loading libraries in an
insecure manner. This can be exploited to load arbitrary libraries by tricking
a user into opening a UENC file located on a remote WebDAV or SMB share.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A workaround is to disable loading of libraries from WebDAV and remote network
shares and to disable the WebClient service ";

tag_summary = "This host is installed with UltraEdit and is prone
to insecure library loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902307");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3402");
  script_bugtraq_id(43183);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("UltraEdit Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41403");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-09/0227.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ueName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("UltraEdit" >< ueName)
  {
    ## Check for UltraEdit Installed location
    uePath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(uePath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:uePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:uePath + "\Uedit32.exe");

      ## Check for UltraEdit File Version
      ueVer = GetVer(file:file, share:share);
      if(ueVer != NULL)
      {
        ## Check for UltraEdit version <= 16.20.0.1009
        if(version_is_less_equal(version:ueVer, test_version:"16.20.0.1009")){
          security_message(0) ;
        }
      }
    }
  }
}
