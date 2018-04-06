###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kingsoft_antivirus_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Kingsoft Antivirus 'KisKrnl.sys' Driver Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow local users to cause a denial
of service condition.

Impact Level: Application.";

tag_affected = "Kingsoft Antivirus version 2011.1.13.89 and prior.";

tag_insight = "The flaw is due to an error when handling system service calls
in the 'kisknl.sys' driver which can be exploited to cause a page fault error
in the kernel and crash the system.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Kingsoft Antivirus and is prone to
denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901176");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0515");
  script_bugtraq_id(45821);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Kingsoft Antivirus 'KisKrnl.sys' Driver Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42937");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64723");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15998/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
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

if(!registry_key_exists(key:"SOFTWARE\Kingsoft")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" +
                   "Kingsoft Internet Security";

if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Kingsoft Antivirus DisplayName
ksantName = registry_get_sz(key:key, item:"DisplayName");

if("Kingsoft AntiVirus" >< ksantName)
{
  ## Check for Kingsoft Antivirus DisplayIcon
  ksantPath = registry_get_sz(key:key + item, item:"DisplayIcon");
  if(!isnull(ksantPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ksantPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ksantPath);

    ## Check for Kingsoft Antivirus .exe File Version
    ksantVer = GetVer(file:file, share:share);
    if(ksantVer != NULL)
    {
      ## Check for Kingsoft Antivirus version <= 2011.1.13.89
      if(version_is_less_equal(version:ksantVer, test_version:"2011.1.13.89")){
        security_message(0) ;
      }
    }
  }
}
