###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aceftp_remote_dir_traversal_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# AceFTP LIST Command Directory Traversal Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into downloading a directory containing files with
  specially crafted filenames from a malicious FTP server.
  Impact Level: Application";
tag_affected = "Visicom Medias AceFTP Freeware/Pro Version 3.80.3 and prior on W
  Windows";
tag_insight = "The flaw is due to input validation errors when processing FTP
  responses to a LIST command. These can be exploited by attackers when
  downloading the directories containing files with directory traversal
  specifiers in the filename.";
tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided
  anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.

  A workaround is to avoid downloading files and directories from untrusted FTP
  servers.
  For updates refer to http://software.visicommedia.com/en/products/";
tag_summary = "The host is installed with AceFTP and is prone to Directory
  Traversal Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800307");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5175");
  script_bugtraq_id(29989);
  script_name("AceFTP LIST Command Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://vuln.sg/aceftp3803-en.html");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30792");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/1954");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

keys = registry_enum_keys(key:key);
foreach item (keys)
{
  aceName = registry_get_sz(item:"DisplayName", key:key + item);

  if("AceFTP 3 Freeware" >< aceName || "AceFTP 3 Pro" >< aceName)
  {
    aceVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!aceVer){
      exit(0);
    }

    if(version_is_less_equal(version:aceVer, test_version:"3.80.3")){
      security_message(0);
      exit(0);
    }
  }
}
