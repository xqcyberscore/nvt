# OpenVAS Vulnerability Test
# $Id: js.scob.trojan.nasl 7332 2017-09-29 14:16:56Z cfischer $
# Description: JS.Scob.Trojan or Download.Ject Trojan
#
# Authors:
# Jeff Adams <jadams@netcentrics.com>
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
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
#

tag_summary = "JS.Scob.Trojan or Download.Ject Trojan

JS.Scob.Trojan or Download.Ject is a simple Trojan that executes a 
JavaScript file from a remote server. 

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer.  The presence of 
Kk32.dll or Surf.dat may indicate a client side infection.  More 
information is available here:

http://www.microsoft.com/security/incident/download_ject.mspx";

tag_solution = "Use Latest Anti Virus to clean machine. Virus Definitions
and removal tools are being released as of 06/25/04";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12286");
  script_version("$Revision: 7332 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-29 16:16:56 +0200 (Fri, 29 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("JS.Scob.Trojan or Download.Ject Trojan");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Jeff Adams");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
   exit(0);
}

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");

if (! rootfile)
	exit(0);

files[0] = string(rootfile, "\\system32\\kk32.dll");
files[1] = string(rootfile, "\\system32\\Surf.dat");

foreach file (files) 
{
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
        file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);
        myread = read_file(file:file, share:share, offset:0,count:4);
        if (myread) {
         security_message(port:0);
         exit(0);
	} 
}

exit(0);
