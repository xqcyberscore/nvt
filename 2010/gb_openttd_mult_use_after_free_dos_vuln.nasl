###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openttd_mult_use_after_free_dos_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# OpenTTD Multiple use-after-free Denial of Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendrgg@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to deny service to
  legitimate users or arbitrary code execution.
  Impact Level: System/Application";
tag_affected = "OpenTTD version before 1.0.5";
tag_insight = "The flaw is due to a use-after-free error, when a client disconnects
  without sending the 'quit' or 'client error' message. This could cause a
  vulnerable server to read from or write to freed memory leading to a denial
  of service or it can also lead to arbitrary code execution.";
tag_solution = "Upgrade to the latest version of OpenTTD 1.0.5 or later,
  For updates refer to http://www.openttd.org";
tag_summary = "This host is installed with OpenTTD and is prone to multiple
  denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800184");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-4168");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("OpenTTD Multiple use-after-free Denial of Service vulnerability");
  script_xref(name : "URL" , value : "http://security.openttd.org/en/CVE-2010-4168");
  script_xref(name : "URL" , value : "http://security.openttd.org/en/patch/28.patch");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
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


## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Openttd Version from Registry
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenTTD";
openttd_ver = registry_get_sz(key:key, item:"DisplayVersion");

if(openttd_ver)
{
  ## Check for Version before 1.0.5
  if(version_is_less(version:openttd_ver, test_version:"1.0.5")){
    security_message(0);
  }
}
