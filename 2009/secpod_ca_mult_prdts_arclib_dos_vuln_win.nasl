###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_mult_prdts_arclib_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# CA Multiple Products 'arclib' Component DoS Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_solution = "Apply the appropriate patches.
  https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=218878

  *****
  NOTE: Ignore this warning if the above mentioned patches are already applied.
  *****";

tag_impact = "Remote attackers can exploit this issue to execute arbitrary code and
  crash the service on affected systems via specially crafted RAR files.
  Impact Level: Application/System";
tag_affected = "eTrust EZ Antivirus 7.1,
  CA Anti-Virus 2007 thruogh 2008,
  CA Internet Security Suite 2007 through Plus 2009 on Windows.";
tag_insight = "Multiple errors occur in the arclib component of the CA Anti-Virus engine
  due to improper handling of RAR files.";
tag_summary = "This host is installed with CA Multiple Products and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900967");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3587", "CVE-2009-3588");
  script_bugtraq_id(36653);
  script_name("CA Multiple Products 'arclib' Component DoS Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53697");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53698");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2852");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ca_mult_prdts_detect_win.nasl");
  script_mandatory_keys("CA/Multiple_Products/Win/Installed");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Get KB for eTrust EZ Antivirus
ezavVer = get_kb_item("CA/eTrust-EZ-AV/Win/Ver");
# Get KB for CA Anti-Virus
caavVer = get_kb_item("CA/AV/Win/Ver");
# Get KB for CA Internet Security Suite
caissVer = get_kb_item("CA/ISS/Win/Ver");

if((ezavVer =~ "^7\.1") || (caavVer =~ "^(8|9|10)\..*") ||
   (caissVer =~ "^(3|4|5)\..*"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\ComputerAssociates\ISafe",
                            item:"ArclibDllPath");
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

  dllVer = GetVer(file:file, share:share);
  if(dllVer)
  {
    # Check for Arclib.dll version < 8.1.4.0
    if(version_is_less(version:dllVer, test_version:"8.1.4.0")){
      security_message(0);
    }
  }
}
