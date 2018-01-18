###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_estk_insecure_lib_load_vuln_win.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Adobe ExtendedScript Toolkit (ESTK) Insecure Library Loading Vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks.

Impact Level: Application.";

tag_affected = "Adobe ExtendedScript Toolkit (ESTK) CS5 3.5.0.52 on windows.";

tag_insight = "The flaw is due to the application insecurely loading certain
librairies from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network
share.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Adobe ExtendedScript Toolkit (ESTK)
and is prone to insecure library loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801510");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3155");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe ExtendedScript Toolkit (ESTK) Insecure Library Loading Vulnerability (Windows)");
  script_xref(name : "URL" , value : "https://launchpad.net/bugs/cve/2010-3155");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14785/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  adName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Adobe ExtendScript Toolkit" >< adName)
  {
    ## Get Adobe Adobe ExtendScript Toolkit version from registry
    adVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(adVer))
    {
      ## Check for Adobe ExtendScript Toolkit CS5 3.5.0.52
      if(version_is_equal(version:adVer, test_version:"3.5.0.52"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
