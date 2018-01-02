###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lhasa_untrusted_search_path_vuln.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Lhasa Untrusted search path vulnerability
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
  Impact Level: Application";
tag_affected = "Lhasa version 0.19 and prior";

tag_insight = "The flaw exists due to Lhasa, which loads certain executables (.exe) when
  extracting files.";
tag_solution = "Upgrade to the Lhasa version 0.20 0r later
  For updates refer to http://www.digitalpad.co.jp/~takechin/download.html#lhasa";
tag_summary = "This host is installed with Lhasa and is prone to untrusted search
  path vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801461");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-2369");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Lhasa Untrusted search path vulnerability");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN88850043/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/ja/contents/2010/JVNDB-2010-000038.html");

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get the path for Lhasa
lhPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");
if(lhPath != NULL)
{
  lhPath = lhPath + "\Lhasa\README.txt";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:lhPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:lhPath);
  readmeText = read_file(share:share, file:file, count:1000);

  if(readmeText != NULL)
  {
    ## Confirm the application is Lhasa
    if ("LHASA" >< readmeText)
    {
      ## Get the .exe path
      lhPath = lhPath - "\README.txt" + "\Lhasa.exe";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:lhPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:lhPath);
      lhVer = GetVer(file:file, share:share);

      if(lhVer != NULL)
      {
        ## Check for Lhasa version <= 0.19
        if(version_is_less_equal(version:lhVer, test_version:"0.19")){
          security_message(0);
        }
      }
    }
  }
}
