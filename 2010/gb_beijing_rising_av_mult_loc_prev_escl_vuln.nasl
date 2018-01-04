###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beijing_rising_av_mult_loc_prev_escl_vuln.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Rising Antivirus Drivers Multiple Local Privilege Escalation Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to corrupt kernel memory and
  execute arbitrary code on the system with kernel privileges.
  Impact Level: System/Application";
tag_affected = "Rising Antivirus 2008/2009/2010 on windows";
tag_insight = "The flaw exists due to error in the 'HookCont.sys', 'HookNtos.sys',
  'HOOKREG.sys', 'HookSys.sys' and 'RsNTGdi.sys' drivers while processing
  specially-crafted IOCTL requests.";
tag_solution = "Run SmartUpdate to Get the Fixed Drivers";
tag_summary = "This host is installed with Rising Antivirus and is prone to local privilege
  escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800178");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_bugtraq_id(37951);
  script_cve_id("CVE-2010-1591");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Rising Antivirus Drivers Multiple Local Privilege Escalation Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38335");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55869");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0218");
  script_xref(name : "URL" , value : "http://www.ntinternals.org/ntiadv0902/ntiadv0902.html");
  script_xref(name : "URL" , value : "http://www.ntinternals.org/ntiadv0805/ntiadv0805.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
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

## Windows Confirmation
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Rising AV Disaply Name
key = "SOFTWARE\rising\Rav";
risingDisplayName = registry_get_sz(key:key, item:"name");

## Confirm the AV is 2008/2009/2010
if(risingDisplayName =~ "Rising AntiVirus Software (2008|2009|2010)")
{
  ## Get System32 path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!sysPath){
    exit(0);
  }

  ## Get File Version of 'RsNTGdi.sys' driver file
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:sysPath + "\drivers\RsNTGdi.sys");
  risingDriverVer  = GetVer(file:file, share:share);

  if(risingDriverVer)
  {
    ## Check version is 20.0 to 22.0.0.7
    if(version_in_range(version:risingDriverVer, test_version:"20.0",
                                                 test_version2:"22.0.0.5")){
      security_message(0);
    }
  }
}
