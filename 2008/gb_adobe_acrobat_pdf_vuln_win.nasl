###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_pdf_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Adobe Acrobat 9 PDF Document Encryption Weakness Vulnerability (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow attackers to steal or guess document's
  password via a brute force attacks.
  Impact Level: Application";
tag_affected = "Adobe Acrobat version 9.0 on Windows.";
tag_insight = "The flaw is due to the way it handles encryption standards.";
tag_solution = "Upgrade Adobe Acrobat version 9.3.2 or later,
  For updates refer to http://www.adobe.com/products/";
tag_summary = "This host has Adobe Acrobat installed and is prone to encryption
  weakness vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800078");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5331");
  script_bugtraq_id(32610);
  script_name("Adobe Acrobat 9 PDF Document Encryption Weakness Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/security/2008/12/acrobat_9_and_password_encrypt.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  adobeName = registry_get_sz(item:"DisplayName", key:key +item);
  if("Adobe Acrobat" >< adobeName)
  {
    adobeVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!adobeVer){
      exit(0);
    }

    if(adobeVer =~ "^9\.0(\.0)?$"){
      security_message(0);
    }
    exit(0);
  }
}
