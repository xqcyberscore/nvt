###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_subtitle_translation_wizard_bof_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# Subtitle Translation Wizard '.srt' File Stack Based Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code. Failed exploit attempts will result in denial-of-service
conditions.

Impact Level: Application.";

tag_affected = "Subtitle Translation Wizard 3.0";

tag_insight = "The flaw exists due to a boundary error when processing subtitle
files in 'st-wizard.exe', which causes a stack-based buffer overflow via '.srt'
file containing an overly long string.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Subtitle Translation Wizard and is
prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801426");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-2440");
  script_bugtraq_id(41026);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Subtitle Translation Wizard '.srt' File Stack Based Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40303");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13965/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Subtitle Translation Wizard_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Subtitle Translation Wizard DisplayName
stwName = registry_get_sz(key:key, item:"DisplayName");
if("Subtitle Translation Wizard" >< stwName)
{
  ## Grep for the version
  stwVer = eregmatch(pattern:"Subtitle Translation Wizard ([0-9.]+)" , string:stwName);
  if(stwVer[1] != NULL)
  {
    ## Check for Subtitle Translation Wizard version equal to 3.0
    if(version_is_equal(version:stwVer[1], test_version:"3.0")){
        security_message(0) ;
    }
  }
}
