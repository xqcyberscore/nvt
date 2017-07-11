###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_os_detection.nasl 6226 2017-05-26 21:05:06Z cfi $
#
# Nmap OS Identification (NASL wrapper)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Nmap can be found at :
# <http://nmap.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108021");
  script_version("$Revision: 6226 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-26 23:05:06 +0200 (Fri, 26 May 2017) $");
  script_tag(name:"creation_date", value:"2016-11-21 12:08:04 +0100 (Mon, 21 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap OS Identification (NASL wrapper)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("toolcheck.nasl", "ping_host.nasl", "secpod_open_tcp_ports.nasl");
  script_mandatory_keys("Tools/Present/nmap", "TCP/PORTS");

  script_xref(name:"URL", value:"https://nmap.org/book/man-os-detection.html");
  script_xref(name:"URL", value:"https://nmap.org/book/osdetect.html");

  script_add_preference(name:"Guess OS more aggressively (safe checks off only)", type:"checkbox", value:"no");
  script_add_preference(name:"Guess OS more aggressively even if safe checks are set", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin runs nmap to identify the remote Operating System.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("network_func.inc");

SCRIPT_DESC = "Nmap OS Identification (NASL wrapper)";

if( get_kb_item( "Host/dead" ) ) exit( 0 );

tmpfile = NULL;

function on_exit() {
  if( tmpfile && file_stat( tmpfile ) ) unlink( tmpfile );
}

safe_opt = script_get_preference( "Guess OS more aggressively even if safe checks are set" );
if( safe_opt && "yes" >< safe_opt ) {
  safe = 0;
} else {
  safe = safe_checks();
}

ip = get_host_ip();

i = 0;
argv[i++] = "nmap";

if( TARGET_IS_IPV6() ) {
  argv[i++] = "-6";
}

argv[i++] = "-n";
argv[i++] = "-Pn"; # Also run if ping failed
argv[i++] = "-sV"; # nmap is able to detect the OS from the service scan like: Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel:3.2.40
argv[i++] = "-oN"; # -oG currently doesn't have the CPE in its output

tmpdir = get_tmp_dir();
if( tmpdir && strlen( tmpdir ) ) {
  tmpfile = strcat( tmpdir, "nmap-", ip, "-", rand() );
  fwrite( data:" ", file:tmpfile ); # make sure that tmpfile could be created. Then we can check that tmpfile exist with file_stat().
}

if( tmpfile && file_stat( tmpfile ) ) {
  argv[i++] = tmpfile;
} else {
  argv[i++] = "-";
}

argv[i++] = "-O";
argv[i++] = "--osscan-limit"; # Limit OS detection to promising targets (nmap will exit if not at least one open and one closed TCP port was found)

if( ! safe ) {
  p = script_get_preference( "Guess OS more aggressively (safe checks off only)" );
  if( "yes" >< p ) argv[i++] = "--osscan-guess";
}

argv[i++] = "-p";
# -O needs at least one open and one closed TCP port
openPorts = get_all_tcp_ports_list();

foreach port( openPorts ) {

  # non_simult_ports so ignoring these here. Also removing 27960 which is known to crash (see find_service.nasl)
  if( port == "139" || port == "445" || port == "27960" ) continue;

  if( isnull ( portList ) ) {
    portList = port;
  } else {
    portList += "," + port;
  }
}

# Also add a few low-ports as nmap OS detection behaves strange with only closed/filtered high ports
foreach port( make_list( "21", "22", "25", "80", "443" ) ) {
  if( ! in_array( search:port, array:openPorts ) ) {
    portList += "," + port;
  }
}

# -O needs at least one open and one closed TCP port so adding five potentially closed ports here

# Amout of closed ports to add. Don't add more then 5 as random ports between 1xxxx and 5xxxx are chosen down below based on this
numClosedPorts = 3;

# Choose a high port for the needed closed port
for( j = 1; j <= numClosedPorts; j++ ) {

  closedPort = rand_str( length:( 4 ), charset:'0123456789' );

  # Choose the closed port in the range of i0000 - i9999 and make sure its not already in the list
  while( j + closedPort >< portList ) {
    closedPort = rand_str( length:( 4 ), charset:'0123456789' );
  }
  portList += "," + j + closedPort;
}

argv[i++] = portList;

argv[i++] = ip;

res = pread( cmd:"nmap", argv:argv, cd:1 );

if( "TCP/IP fingerprinting (for OS scan) requires root privileges." >< res ) {
  log_message( port:0, data:"ERROR: TCP/IP fingerprinting (for OS scan) requires root privileges but scanner is running under an unprivileged user. Start scanner as root to get this scan working.");
  exit( 0 );
}

if( tmpfile && file_stat( tmpfile ) ) {
  res = fread( tmpfile );
}

if( ! res ) exit( 0 ); # error

# We don't want to report the OS if nmap is not absolutely sure
if( "JUST GUESSING" >< res || "test conditions non-ideal" >< res || "No exact OS matches for host" >< res ) {

  # Remove unknown fingerprints as we don't want to flood the report with this data
  pattern = "([0-9]+)( (service|services) unrecognized despite returning data).*\);";
  if( eregmatch( pattern:pattern, string:res ) ) {
    res = ereg_replace( string:res, pattern:pattern, replace:"*** unknown fingerprints replaced ***" );
  }

  register_unknown_os_banner( banner:res, banner_type_name:"Nmap TCP/IP fingerprinting", banner_type_short:"nmap_os" );
  exit( 0 );
}

# Example: OS details: Linux 3.8 - 4.5
osTxt = eregmatch( string:res, pattern:"OS details: ([ -~]+)" );

# Example: OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
osCpe = eregmatch( string:res, pattern:"OS CPE: ([ -~]+)" );
sep = " "; # Seperator to split multiple CVEs

if( isnull( osTxt ) || isnull( osCpe ) ) {

  # Example from -sV: "Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel:2, cpe:/o:linux:linux_kernel:3.2.40"
  osTxt = eregmatch( string:res, pattern:"OS: ([ -~]+);");
  osCpe = eregmatch( string:res, pattern:"CPE: ([ -~]+)" );
  sep = ", "; # Seperator to split multiple CVEs
}

if( ! isnull( osTxt ) && ! isnull( osCpe ) ) {

  cpes = split( osCpe[0], sep:sep, keep:FALSE );
  cpe = cpes[max_index( cpes ) - 1];

  if( "linux" >< tolower( osTxt[1] ) || "linux" >< cpe ) {
    runs_key = "unixoide";
  } else if( "windows" >< tolower( osTxt[1] ) || "windows" >< cpe ) {
    runs_key = "windows";
  } else {
    runs_key = "unknown";
  }

  register_and_report_os( os:osTxt[1], cpe:cpe, banner_type:"Nmap TCP/IP fingerprinting", banner:'\n' + osTxt[0] + '\n' + osCpe[0], desc:SCRIPT_DESC, runs_key:runs_key );

}

exit( 0 );
