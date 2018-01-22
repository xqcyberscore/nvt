###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hyleos_chemview_activex_mult_bof_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# Hyleos ChemView ActiveX Control Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_affected = "Hyleos ChemView ActiveX Control version 1.9.5.1 and prior.";
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code
within the context of the affected application.

Impact Level: Application";
tag_insight = "The flaws are due to two boundary errors in the 'HyleosChemView.ocx'
which can be exploited to cause stack-based buffer overflows by passing
strings containing an overly large number of white-space characters to the
'SaveasMolFile()' and 'ReadMolFile()' methods.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A Workaround is to set  the Killbit for the vulnerable CLSID
{C372350A-1D5A-44DC-A759-767FC553D96C}";
tag_summary = "This host is installed with Hyleos ChemView ActiveX Control and is
  prone to multiple Buffer Overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900749");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0679");
  script_bugtraq_id(38225);
  script_name("Hyleos ChemView ActiveX Control Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38523");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11422");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1002-advisories/chemviewx-overflow.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1002-exploits/hyleoschemview-heap.rb.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_hyleos_chemview_detect.nasl");
  script_mandatory_keys("Hyleos/ChemViewX/Ver");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

chemVer = get_kb_item("Hyleos/ChemViewX/Ver");
if(!chemVer){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
      exit(0);
}

if(!version_is_less_equal(version:chemVer, test_version:"1.9.5.1")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Hyleos - ChemViewX" >< name)
  {
    chemPath = registry_get_sz(key:key + item, item:"InstallLocation");
    dllPath = chemPath + "\Common\HyleosChemView.ocx";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    dllVer = GetVer(file:file, share:share);
    if(dllVer != NULL)
    {
      # Grep for HyleosChemView.ocx version 1.9.5.1 and prior
      if(version_is_less_equal(version:dllVer, test_version:"1.9.5.1"))
      {
        # Workaround check
        if(is_killbit_set(clsid:"{C372350A-1D5A-44DC-A759-767FC553D96C}") == 0){
          security_message(0);
        }
      }
    }
  }
}
