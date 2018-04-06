###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_prdts_int_overflow_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# F-Secure Product(s) Integer Overflow Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to craft the archive
  files with arbitrary codes and can cause integer overflow in the context
  of an affected application.
  Impact Level: System/Application";
tag_affected = "F-Secure AntiVirus 2008 and prior
  F-Secure AntiVirus Workstation
  F-Secure Internet Security 2008 and prior
  F-Secure Client Security
  F-Secure Internet Gatekeeper for Windows 6.61 and prior";
tag_insight = "The vulnerability is due to an integer overflow error while scanning
  contents of specially crafted RPM files inside the archives.";
tag_solution = "Apply patch
  http://www.f-secure.com/security/fsc-2008-3.shtml";
tag_summary = "This host is installed with F-Secure Product(s) and is prone to
  Integer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800356");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6085");
  script_bugtraq_id(31846);
  script_name("F-Secure Product(s) Integer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32352");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Oct/1021073.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Data Fellows\F-Secure")){
  exit(0);
}

# Get the path for F-Secure Anti-Virus, Client Security, Workstation
# and Internet Security
fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure\Anti-Virus",
                         item:"Path");
if(!fsPath)
{
  # Get the path for Internet Gatekeeper and Anti-Virus for Microsoft Exchange
  fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure" +
                               "\Content Scanner Server", item:"Path");
  if(!fsPath){
    exit(0);
  }
}

fsPath = fsPath + "\fm4av.dll";
share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:fsPath);
file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:fsPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Grep for fm4av.dll version prior to 2.0.14340.7363
if(version_is_less(version:dllVer, test_version:"2.0.14340.7363")){
  security_message(0);
}
