###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_incredimail_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Incredimail Malformed MIME Message DoS Vulnerability
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
tag_affected = "Incredimail 5.8.5.3710 (5853710) and prior on Windows.";
tag_insight = "Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822
  headers.";
tag_solution = "Upgrade to latest version of Incredimail-5.8.5.3849 (5853849)
  http://www.incredimail.com/english/download/";
tag_summary = "This host has Incredimail installed and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800085");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5429");
  script_name("Incredimail Malformed MIME Message DoS Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499038");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499045");
  script_xref(name : "URL" , value : "http://mime.recurity.com/cgi-bin/twiki/view/Main/AttackIntro");

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
include("version_func.inc");
include("secpod_smb_func.inc");

if(!(get_kb_item("SMB/WindowsVersion"))){
  exit(0);
}

mailVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\IncrediMail", item:"DisplayVersion");
if(!mailVer){
  exit(0);
}

mailVer = eregmatch(pattern:"([0-9.]+)", string:mailVer);
if(mailVer[1] != NULL)
{
  if(version_is_less_equal(version:mailVer[1], test_version:"5.8.5.3710")){
    security_message(0);
  }
}
