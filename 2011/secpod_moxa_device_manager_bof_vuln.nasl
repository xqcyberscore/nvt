###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_moxa_device_manager_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# MOXA Device Manager MDM Tool Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code.
  Impact Level: Application.";
tag_affected = "Moxa Device Manager version prior to 2.3";

tag_insight = "The flaw is due to a stack-based buffer overflow error in 'strcpy()'
  function in 'MDMUtil.dll' within MDM Tool.";
tag_solution = "Upgrade to the Moxa Device Manager version 2.3 or later,
  For updates refer to http://www.moxa.com/support/download.aspx?d_id=2669";
tag_summary = "This host is installed with MOXA Device Manager and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902345");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2010-4741");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MOXA Device Manager MDM Tool Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/237495");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/MORO-8D9JX8");
  script_xref(name : "URL" , value : "http://reversemode.com/index.php?option=com_content&task=view&id=70&Itemid=1");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

## Get Install Location From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("MOXA Device Manager" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      ## Check for MOXA Device Manager version less that 2.3.0
      if(version_is_less(version:ver, test_version:"2.3.0"))
      {
        security_message(0) ;
        exit(0);
      }
    }
  }
}
