###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_address_book_insecure_lib_load_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Microsoft Windows Address Book Insecure Library Loading Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to load arbitrary
libraries by tricking a user into opening a vCard (.vcf).

Impact Level: System";

tag_affected = "Microsoft Windows 7
Microsoft Windows XP SP3 and prior.
Microsoft Windows Vista SP 2 and prior.
Microsoft Windows Server 2008 SP 2 and prior.
Microsoft Windows Server 2003 SP 2 and prior.";

tag_insight = "The flaw is due to the way Microsoft Address Book loads
libraries in an insecure manner.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft Address Book and is prone
to insecure library loading vulnerability.

This NVT has been replaced by NVT secpod_ms10-096.nasl
(OID:1.3.6.1.4.1.25623.1.0.901169).";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801457");
  script_version("$Revision: 8296 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-3143");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Address Book Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14778/");
  script_xref(name : "URL" , value : "http://www.attackvector.org/new-dll-hijacking-exploits-many/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-096.nasl

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1) <= 0){
 exit(0);
}

## Check the existence of Address Book for Win XP and Win 2003
key = "SOFTWARE\Clients\Contacts\Address Book";
if(registry_key_exists(key:key))
{
  key = "SOFTWARE\Microsoft\Active Setup\Installed Components\";
  if(registry_key_exists(key:key))
  {
  foreach item (registry_enum_keys(key:key))
  {
    addName = registry_get_sz(key:key + item, item:"ComponentID");
    if("WAB" >< addName)
    {
      addVer = registry_get_sz(key:key + item, item:"Version");
      if(addVer != NULL)
      {
        if(version_is_less_equal(version:addVer, test_version:"6.0.2900.5512"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
  }
}

## Check the existence of the Windows Contacts for windows 7 and win vista
key = "SOFTWARE\Microsoft\Windows Mail\Advanced Settings\Contacts\";
if(!registry_key_exists(key:key)){
 exit(0);
}

winName = registry_get_sz(key:key, item:"Text");
if("Windows Contacts" >< winName){
  security_message(0);
}
