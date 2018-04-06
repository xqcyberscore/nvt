###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nod32_email_message_dos.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# NOD32 E-mail message Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can crash the application.";
tag_affected = "NOD32 AntiVirus version 2.70.0039.000 and prior.";
tag_insight = "This flaw is due to improper handling of multipart/mixed e-mail messages with
  many MIME parts and Email messages with many Content-type: message/rfc822
  headers.";
tag_solution = "Upgrade to the latest version 3.x,
  http://www.eset.com/download";
tag_summary = "This host is installed with NOD32 Antivirus and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800203");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5425");
  script_name("NOD32 Email Message Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/papers/general/mime-dos.txt");

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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ESET\ESET Security\CurrentVersion\Info")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

entries = registry_enum_keys(key:key);
foreach item (entries)
{
  node = registry_get_sz(key:key + item, item:"DisplayName");
  if("ESET NOD32 Antivirus" >< node)
  {
    nodeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(nodeVer != NULL)
    {
      # Grep for version 2.70.0039.0000 or prior
      if(version_is_less_equal(version:nodeVer, test_version:"2.70.0039.0000")){
        security_message(0);
      }
    }
    exit(0);
  }
}
