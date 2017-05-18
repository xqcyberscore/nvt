# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-009.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Microsoft ISA Server DNS - Denial Of Service (MS03-009)
#
# Authors:
# Bekrar Chaouki - A.D Consulting <bekrar@adconsulting.fr>
#
# Copyright:
# Copyright (C) 2003 A.D.Consulting
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

tag_summary = "A flaw exists in the ISA Server DNS intrusion detection application filter.
An attacker could exploit the vulnerability by sending a specially formed 
request to an ISA Server computer that is publishing a DNS server, which 
could then result in a denial of service to the published DNS server.";

tag_solution = "see http://www.microsoft.com/technet/security/bulletin/ms03-009.mspx";

if(description)
{
 script_id(11433);
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7145);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2003-0011");

 name = "Microsoft ISA Server DNS - Denial Of Service (MS03-009)";

 script_name(name);
 

 summary = "Checks for ISA Server DNS HotFix SP1-256";

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 A.D.Consulting");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports( 139, 445 );
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256");
if(!fix)security_message(port);
