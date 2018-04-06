###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_internet_sec_suite_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Kaspersky Internet Security Suite Malformed MIME Message DoS Vulnerability
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

tag_impact = "Successful exploitation could result in application crash.
  Impact Level: Application";
tag_affected = "Kaspersky Internet Security Suite 2009 on Windows.";
tag_insight = "Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822
  headers.";
tag_solution = "Upgrade to latest version of Kaspersky Internet Security Suite
  http://www.kaspersky.com/downloads";
tag_summary = "This host has Kaspersky Internet Security Suite installed and is
  prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800086");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5426");
  script_name("Kaspersky Internet Security Suite Malformed MIME Message DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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
include("secpod_smb_func.inc");

if(!(get_kb_item("SMB/WindowsVersion"))){
  exit(0);
}

uninstall = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:uninstall)){
    exit(0);
}

foreach key (registry_enum_keys(key:uninstall))
{
  kisName = registry_get_sz(key:uninstall + key, item:"DisplayName");
  if("Kaspersky Internet Security" >< kisName)
  {
    # Kaspersky Internet Security 2009
    if("Kaspersky Internet Security 2009" >< kisName){
      security_message(0);
    }
    exit(0);
  }
}
