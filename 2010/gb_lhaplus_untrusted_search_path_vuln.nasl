###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lhaplus_untrusted_search_path_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Lhaplus Untrusted search path Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  with the privilege of the running application.
  Impact Level: Application.";
tag_affected = "Lhaplus version 1.57 and prior";

tag_insight = "The flaw exists because the application loading libraries and executable in
  an insecure manner.";
tag_solution = "Upgrade to the Lhaplus version 1.58
  For updates refer to http://www7a.biglobe.ne.jp/~schezo/";
tag_summary = "This host is installed with Lhaplus and is prone to
  untrusted search path vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801462");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-2368", "CVE-2010-3158");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Lhaplus Untrusted search path Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41742");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN82752978/index.html");
  script_xref(name : "URL" , value : "http://www.ipa.go.jp/about/press/20101012.html");
  script_xref(name : "URL" , value : "http://www7a.biglobe.ne.jp/~schezo/dll_vul.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\HoeHoe\Lhaplus")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Lhaplus";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get the path for Lhaplus.exe
lhpPath = registry_get_sz(key:key + item, item:"UninstallString");
if(!isnull(lhpPath))
{
  lhpPath = lhpPath - "\Uninst.exe" + "\Lhaplus.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:lhpPath);
  fire = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:lhpPath);

  ## Check for Lhaplus.exe File Version
  lhpVer = GetVer(file:fire, share:share);
  if(lhpVer != NULL)
  {
    ## Check for Lhaplus version <= 1.5.7
    if(version_is_less_equal(version:lhpVer, test_version:"1.5.7")){
        security_message(0) ;
    }
  }
}
