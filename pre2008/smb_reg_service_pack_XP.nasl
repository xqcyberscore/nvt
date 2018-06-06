###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_reg_service_pack_XP.nasl 10087 2018-06-06 05:55:17Z cfischer $
#
# SMB Registry : XP Service Pack version
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# Copyright:
# Copyright (C) 2002 Alert4Web.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11119");
  script_version("$Revision: 10087 $");
  script_bugtraq_id(10897, 11202);
  script_cve_id("CVE-1999-0662");
  script_tag(name:"last_modification", value:"$Date: 2018-06-06 07:55:17 +0200 (Wed, 06 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SMB Registry : XP Service Pack version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Alert4Web.com");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script reads the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
  to determine the Service Pack the host is running.

  This NVT has been replaced by NVT 'Microsoft Windows Service Pack Missing Multiple Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.902909).");

  script_tag(name:"insight", value:"By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
  it was possible to determine that the remote Windows XP system is not up to date.");

  script_tag(name:"solution", value:"Apply Windows XP Service Pack 2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("smb_nt.inc");

port = kb_smb_transport();

win = get_kb_item("SMB/WindowsVersion");
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.1")
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);
 else
 {
  security_message(data:"The remote Windows XP system has no service pack applied.", port:port);
  exit(0);
 }

 if (sp == "Service Pack 2")
 {
  log_message(data:"The remote Windows XP system has " + sp + " applied.", port:port);
  exit(0);
 }

 if(sp == "Service Pack 1")
 {
  security_message(data:"The remote Windows XP system has " + sp + " applied. Apply SP2 to be up-to-date.", port:port);
  exit(0);
 }
}

exit(99);