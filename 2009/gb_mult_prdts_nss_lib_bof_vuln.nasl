###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mult_prdts_nss_lib_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Multiple Products NSS Library Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code in
  the context of the affected application and may lead to denial of service.";
tag_affected = "Firefox/Thunderbird/SeaMonkey/Evolution/Pidgin/AOL Instant Messenger
  containing NSS library before 3.12.3.";
tag_insight = "A flaw exists in the regular expression parser used in the NSS library to match
  common names in certificates and may result in a heap based buffer overflow.
  It can be exploited via a long domain name in the subject's Common Name (CN)
  field of an X.509 certificate, related to the cert_TestHostName function.";
tag_solution = "Upgrade to NSS library 3.12.3 or later.
  http://www.mozilla.org/projects/security/pki/nss/tools/";
tag_summary = "This host is installed with Firefox or Thunderbird or SeaMonkey
  or Evolution or Pidgin or AOL Instant Messenger Product(s) which is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800920");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2404");
  script_bugtraq_id(35891);
  script_name("Multiple Products NSS Library Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36102");
  script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1185.html");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512912");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

commonPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");

if(!commonPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:commonPath);
allFiles = make_list();

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");
  # Check for Evolution
  if(prdtName == "Evolution")
  {
    evolutionPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(evolutionPath)
    {
      evolutionFile = evolutionPath + "\bin\nss3.dll";
      allFiles = make_list(allFiles, evolutionFile);
    }
  }
  # Check for AOL Instant Messenger or AIM
  else if("AOL Instant Messenger" >< prdtName)
  {
    aolFile = commonPath + "\AIM\nss3.dll";
    allFiles = make_list(allFiles, aolFile);
  }
  else if("AIM" >< prdtName)
  {
    aimPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(aimPath)
    {
      aimFile = aimPath - "\uninst.exe" + "\nss3.dll";
      allFiles = make_list(allFiles, aimFile);
    }
  }
  # Check for Firefox
  else if("Firefox" >< prdtName)
  {
    firefoxFile = commonPath + "\Mozilla Firefox\nss3.dll";
    allFiles = make_list(allFiles, firefoxFile);
  }
  # Check for Thunderbird
  else if ("Thunderbird" >< prdtName)
  {
    thunderbirdFile = commonPath + "\Mozilla Thunderbird\nss3.dll";
    allFiles = make_list(allFiles, thunderbirdFile);
  }
  # Check for Pidgin
  else if ("Pidgin" >< prdtName){
    pidginFile = commonPath + "\Pidgin\nss3.dll";
    allFiles = make_list(allFiles, pidginFile);
  }
  # Check for SeaMonkey
  else if ("SeaMonkey" >< prdtName){
    seamonkeyFile = commonPath + "\mozilla.org\SeaMonkey\nss3.dll";
    allFiles = make_list(allFiles, seamonkeyFile);
  }
}

foreach prdtFile (allFiles)
{
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:prdtFile);
  dllVer = GetVer(share:share, file:file);

  # Check for NSS Version prior to 3.12.3
  if((dllVer != NULL) && version_is_less(version:dllVer, test_version:"3.12.3"))
  {
    security_message(0);
    exit(0);
  }
}
